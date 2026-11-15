#!/usr/bin/env bash
#
# Build and publish a release from this checkout.
#
# This script is the release pipeline, not the workflow beside it. A tag push
# runs the preflight only (.github/workflows/release.yml): publishing needs the
# signing key and the two-host stamp, neither of which belongs in CI. It builds
# the binaries, the .deb and .rpm, the tarballs and the SBOM, signs SHA256SUMS,
# then uploads them with `gh`.
#
#   scripts/release.sh                 # build, then create or update the release
#   scripts/release.sh --no-upload     # build into dist/ and stop
#   scripts/release.sh --dry-run       # print what would be built and uploaded
#   scripts/release.sh --skip-remote "why"   # release without a recent two-host run
#   scripts/release.sh --skip-arm "why"      # release without an aarch64 artifact
#   scripts/release.sh --skip-fuzz "why"     # release without the bounded fuzz run
#
# Releases are signed with an SSH key (`ssh-keygen -Y sign`, OpenSSH >= 8.0):
# the private key lives at ~/.config/vallum/release-signing-key (or
# $VALLUM_RELEASE_KEY) and the public half is committed at
# packaging/vallum-release.pub — the repository is the trust anchor, and
# install.sh verifies SHA256SUMS.sig before trusting any checksum.
#
# Nothing here is remembered, it is checked. A tag whose tree has the wrong
# version, a changelog that does not mention the release, a tarball missing a
# unit, or a tree that has never crossed two real hosts — each of those is a
# refusal, not a warning, because each of them has happened.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

REPO="KidIkaros/vallum"
DRY=0
UPLOAD=1
SKIP_REMOTE=""
SKIP_ARM=""
SKIP_FUZZ=""
SKIP_STALE=""
SKIP_DESKTOP=""
MIN_FREE_GB="${MIN_FREE_GB:-15}"
SIGN_KEY="${VALLUM_RELEASE_KEY:-$HOME/.config/vallum/release-signing-key}"
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY=1 ;;
        --no-upload) UPLOAD=0 ;;
        --skip-remote)
            shift
            SKIP_REMOTE="${1:-}"
            [ -n "$SKIP_REMOTE" ] || { echo "--skip-remote needs a reason" >&2; exit 1; }
            ;;
        --skip-arm)
            shift
            SKIP_ARM="${1:-}"
            [ -n "$SKIP_ARM" ] || { echo "--skip-arm needs a reason" >&2; exit 1; }
            ;;
        --skip-fuzz)
            shift
            SKIP_FUZZ="${1:-}"
            [ -n "$SKIP_FUZZ" ] || { echo "--skip-fuzz needs a reason" >&2; exit 1; }
            ;;
        --skip-stale)
            shift
            SKIP_STALE="${1:-}"
            [ -n "$SKIP_STALE" ] || { echo "--skip-stale needs a reason" >&2; exit 1; }
            ;;
        --skip-desktop)
            shift
            SKIP_DESKTOP="${1:-}"
            [ -n "$SKIP_DESKTOP" ] || { echo "--skip-desktop needs a reason" >&2; exit 1; }
            ;;
        -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
    shift
done

say() { printf '\n== %s\n' "$*"; }
run() {
    if [ "$DRY" -eq 1 ]; then
        printf '   would run: %s\n' "$*"
    else
        "$@"
    fi
}

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -n "$version" ] || { echo "cannot read the workspace version" >&2; exit 1; }
tag="v$version"
name="vallum-$tag-x86_64-linux"
name_arm="vallum-$tag-aarch64-linux"

say "release $tag"

# ── Preflight ────────────────────────────────────────────────────────────
# Every check here exists because it has already gone wrong once.
fail() {
    printf '   FAIL  %s\n' "$*" >&2
    echo "refusing to release" >&2
    exit 1
}
ok() { printf '   ok    %s\n' "$*"; }

say "preflight"

# A full release builds two targets plus the gates; v1.7.0 prep once died with
# `No space left on device` because target/debug had grown to 77 GB. Refuse
# early, with the fix, rather than half-way through a build.
free_kb=$(df -Pk "$root" | awk 'NR==2 {print $4}')
if [ "$((free_kb / 1024 / 1024))" -lt "$MIN_FREE_GB" ]; then
    fail "only $((free_kb / 1024 / 1024)) GiB free on the build volume (need $MIN_FREE_GB).
   Reclaim: rm -rf target/debug fuzz/target   (or MIN_FREE_GB=<n> to override)"
fi
ok "$((free_kb / 1024 / 1024)) GiB free on the build volume"

if [ -n "$(git status --porcelain)" ]; then
    git status --short >&2
    fail "the working tree has uncommitted changes; a release is built from a commit"
fi
ok "working tree is clean"

if git rev-parse "$tag" >/dev/null 2>&1; then
    tagged=$(git rev-parse "$tag^{commit}")
    if [ "$tagged" != "$(git rev-parse HEAD)" ]; then
        fail "$tag is at ${tagged:0:7}, but HEAD is $(git rev-parse --short HEAD); move the tag or release the tagged commit"
    fi
    ok "$tag is at HEAD"
else
    ok "$tag does not exist yet; it will be created at HEAD"
fi

grep -q "^## $version" CHANGELOG.md || fail "CHANGELOG.md has no section for $version"
ok "CHANGELOG.md documents $version"

# The two-host gate. A stamp, written by scripts/verify-remote.sh, binds a pass
# to a commit — so "we ran it last month" cannot stand in for this tree.
stamp="${XDG_STATE_HOME:-$HOME/.local/state}/vallum/remote-verified"
if [ -n "$SKIP_REMOTE" ]; then
    printf '   skip  two-host verification: %s\n' "$SKIP_REMOTE"
elif [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$(git rev-parse HEAD)" ]; then
    ok "two hosts verified this commit"
else
    fail "no scripts/verify-remote.sh pass recorded for $(git rev-parse --short HEAD).
   Run: sudo ./scripts/verify-remote.sh <ssh-host>
   Or release anyway with: --skip-remote \"reason\""
fi

# The recorded verdicts. Each gate's verdict names the commit it ran against and
# how many assertions it made, so a verdict from an older tree is VISIBLE rather
# than silently standing in for this one, and a shrinking assertion count is a
# signal that a gate got weaker.
VERDICT_DIR="${VERDICT_DIR:-$PWD/.vallum-verdicts}"
stale_gates=""
if [ -d "$VERDICT_DIR" ]; then
    for vf in "$VERDICT_DIR"/*.json; do
        [ -e "$vf" ] || continue
        v_gate=$(basename "$vf" .json)
        v_commit=$(sed -n 's/.*"commit": "\([^"]*\)".*/\1/p' "$vf")
        v_status=$(sed -n 's/.*"status": "\([^"]*\)".*/\1/p' "$vf")
        v_assert=$(sed -n 's/.*"assertions": \([0-9]*\).*/\1/p' "$vf")
        if [ "$v_commit" = "$(git rev-parse HEAD)" ]; then
            if [ "$v_status" = passed ]; then
                ok "$v_gate passed this commit ($v_assert assertions)"
            else
                fail "$v_gate recorded a FAILED verdict for this commit"
            fi
        else
            printf '   stale %s ran on %s (%s assertions), not this commit\n' \
                "$v_gate" "$(printf '%s' "$v_commit" | cut -c1-7)" "$v_assert"
            stale_gates="$stale_gates $v_gate"
        fi
    done
else
    printf '   note  no verdict records in %s\n' "$VERDICT_DIR"
fi
# A stale verdict used to print and pass, which made shipping on old evidence
# the default. It is now a refusal; the skip is allowed but must be written down.
if [ -n "$stale_gates" ]; then
    if [ -n "$SKIP_STALE" ]; then
        printf '   skip  stale verdicts (%s ): %s\n' "${stale_gates# }" "$SKIP_STALE"
    else
        fail "stale acceptance verdicts:$stale_gates.
   Re-run them on this commit (scripts/accept-*.sh on wingman-vps),
   or release anyway with: --skip-stale \"reason\" (record it in docs/qa/)"
    fi
fi

# The signing key. Releases are only as trustworthy as the verification
# install.sh can do, so an unsigned release is a refusal — except in --dry-run,
# which signs nothing anyway.
if [ "$DRY" -eq 0 ]; then
    [ -f "$SIGN_KEY" ] || fail "no release signing key at $SIGN_KEY.
   Generate one:  ssh-keygen -t ed25519 -f ~/.config/vallum/release-signing-key -C vallum-release
   Then commit the public half: cp ~/.config/vallum/release-signing-key.pub packaging/vallum-release.pub"
    actual=$(ssh-keygen -y -f "$SIGN_KEY" 2>/dev/null || true)
    committed=$(cat packaging/vallum-release.pub 2>/dev/null || true)
    [ -n "$actual" ] && [ -n "$committed" ] || fail "cannot compare $SIGN_KEY with packaging/vallum-release.pub"
    [ "$actual" = "$committed" ] || fail "$SIGN_KEY does not match packaging/vallum-release.pub — sign with the committed key or update the trust anchor"
    ok "signing key matches packaging/vallum-release.pub"
else
    echo "   would verify the release signing key against packaging/vallum-release.pub"
fi

if [ "$DRY" -eq 1 ]; then
    echo "   would run: E2E=1 ./scripts/verify.sh"
else
    say "gate: E2E"
    E2E=1 ./scripts/verify.sh >/tmp/vallum-release-gate.log 2>&1 \
        || { tail -20 /tmp/vallum-release-gate.log >&2; fail "scripts/verify.sh failed (see /tmp/vallum-release-gate.log)"; }
    ok "scripts/verify.sh passed"
fi

# The fuzz gate: the wire parsers get a bounded run on the release commit
# itself. Nightly CI runs longer; this is the smoke pass that keeps "the tag
# was fuzzed" from being an assumption. FUZZ_SECONDS overrides the per-target
# budget; --skip-fuzz records the reason the way --skip-arm does.
if [ "$DRY" -eq 1 ]; then
    echo "   would run: ./scripts/fuzz.sh ${FUZZ_SECONDS:-60}"
elif [ -n "$SKIP_FUZZ" ]; then
    printf '   skip  fuzz: %s\n' "$SKIP_FUZZ"
else
    say "gate: fuzz"
    cargo +nightly fuzz --version >/dev/null 2>&1 \
        || fail "cargo-fuzz missing; cargo +nightly install cargo-fuzz (or --skip-fuzz \"reason\")"
    ./scripts/fuzz.sh "${FUZZ_SECONDS:-60}" >/tmp/vallum-release-fuzz.log 2>&1 \
        || { tail -20 /tmp/vallum-release-fuzz.log >&2; fail "scripts/fuzz.sh found a crash (see /tmp/vallum-release-fuzz.log)"; }
    ok "scripts/fuzz.sh passed (all targets, ${FUZZ_SECONDS:-60}s each)"
fi

say "building"
# `strip = "symbols"` in Cargo.toml removes debug info, not the `file!()`
# literals inside panic and assertion messages — so an unmapped release ships
# the builder's own layout (`/home/…/.cargo/registry/…`) to every downloader.
# Remapping both roots makes those paths anonymous and makes two builders
# produce the same strings. It is exported rather than written into
# `.cargo/config.toml` because `$HOME` cannot be expanded there, and exported
# rather than passed per-command because the aarch64 leg must inherit it.
BUILD_HOME=${HOME:?}
BUILD_CARGO=${CARGO_HOME:-$HOME/.cargo}
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$BUILD_HOME=/build --remap-path-prefix=$BUILD_CARGO=/cargo"
run cargo build --release -p vallum -p vallum-quick

if [ -n "$SKIP_ARM" ]; then
    printf '   skip  aarch64 artifact: %s\n' "$SKIP_ARM"
else
    say "building aarch64"
    if [ "$DRY" -eq 0 ]; then
        # cargo-zigbuild needs no sudo and no system cross toolchain: zig's cc
        # shim translates Rust triples, which a raw `zig cc` wrapper cannot do
        # for cc-rs builds (zstd-sys, via the SDK, compiles C).
        command -v cargo-zigbuild >/dev/null \
            || fail "cargo-zigbuild missing; cargo install cargo-zigbuild --locked (or --skip-arm \"reason\")"
        command -v zig >/dev/null \
            || fail "zig missing; install zig (or --skip-arm \"reason\")"
        run cargo zigbuild --release -p vallum -p vallum-quick --target aarch64-unknown-linux-gnu
        file "target/aarch64-unknown-linux-gnu/release/vallum" | grep -q "ARM aarch64" \
            || fail "the aarch64 artifact is not aarch64"
        ok "aarch64 build (cargo zigbuild)"
    else
        echo "   would cross-build aarch64 (cargo zigbuild)"
    fi
fi

# The remap above is only worth having if it is checked: a dependency built
# without it (a stale `target/`, a wrapper that drops RUSTFLAGS) puts the paths
# straight back. Refuse to package a binary that names the builder.
if [ "$DRY" -eq 0 ]; then
    for bin in vallum vallum-quick; do
        # `|| true`: grep exits 1 on no match, and `set -e` would end the release
        # on the case this check exists to confirm.
        leak=$(grep -aoF "$BUILD_HOME" "target/release/$bin" | head -1 || true)
        [ -z "$leak" ] \
            || fail "target/release/$bin still names $BUILD_HOME — rebuild without a cached copy (cargo clean -p, then retry)"
    done
    ok "no build path in either binary"
else
    echo "   would grep both release binaries for $BUILD_HOME"
fi

say "packaging"
# Completions are generated from the binary, not committed: a stale copy
# advertises flags the binary no longer has, and the manifest check compares
# filenames so it cannot catch that. Generate before cargo-deb reads the asset
# table.
run scripts/gen-completions.sh
if [ "$DRY" -eq 0 ]; then
    # Stale completions once shipped a `teardown` nobody could tab-complete.
    # They are build artifacts now — `packaging/vallum.{bash,zsh,fish}` are
    # gitignored and written from the release binary just above — so there is
    # no committed copy left to go stale. What is still possible is an empty
    # one, which ships a shell that completes nothing, and the tarball check
    # below looks at names, not contents.
    for shell in bash zsh fish; do
        [ -s "packaging/vallum.$shell" ] \
            || fail "packaging/vallum.$shell is empty; gen-completions.sh produced nothing"
    done
    ok "the packaged completions come from this binary and are not empty"
fi
run rm -rf target/debian crates/vallum/target/generate-rpm dist
run cargo deb -p vallum --no-build
run bash -c "cd crates/vallum && cargo generate-rpm"

assemble() {
    local bindir=$1 name=$2
    # One list, shared with the gate that checks it: scripts/package-tarball.sh
    # prints the members it staged, and those are the members asserted below.
    local members
    members=$(BINDIR="$bindir" bash scripts/package-tarball.sh "dist/$name")
    tar -C dist -czf "dist/$name.tar.gz" "$name"
    rm -rf "dist/$name"
    # Inspect what we are about to publish. A release once shipped a tarball
    # without the enrolment unit because a copy line had been edited in the
    # wrong place; nobody noticed until it was installed on a host.
    # grep -c reads the whole listing; `grep -q` would exit on the first
    # match, tar would die on SIGPIPE, and pipefail would turn a present
    # member into a false failure.
    local member
    while read -r member; do
        [ -n "$member" ] || continue
        [ "$(tar -tzf "dist/$name.tar.gz" | grep -xc "$name/$member")" -ge 1 ] \
            || fail "the tarball is missing $member"
    done <<< "$members"
}

say "assembling the tarballs"
if [ "$DRY" -eq 0 ]; then
    assemble target/release "$name"
    [ -n "$SKIP_ARM" ] || assemble target/aarch64-unknown-linux-gnu/release "$name_arm"
    cp target/debian/*.deb dist/ 2>/dev/null || true
    cp crates/vallum/target/generate-rpm/*.rpm dist/ 2>/dev/null || true
    ok "the tarballs carry both binaries, all three units and the man pages"

    if [ -n "$SKIP_DESKTOP" ]; then
        printf '   skip  desktop bundle: %s\n' "$SKIP_DESKTOP"
    elif command -v cargo-tauri >/dev/null 2>&1; then
        say "packaging desktop (vallum-desktop)"
        bash scripts/package-desktop.sh --bundles deb --out-dir dist
        ok "staged vallum-desktop .deb"
    else
        fail "cargo-tauri not found for vallum-desktop bundle (or pass --skip-desktop \"reason\")"
    fi

    say "sbom"
    cargo sbom --output-format spdx_json_2_3 > "dist/vallum-$tag-sbom.spdx.json"
    ok "SBOM: dist/vallum-$tag-sbom.spdx.json (crates.io graph; the SDK is a git dependency)"

    say "signing"
    ( cd dist && sha256sum *.deb *.rpm *.tar.gz > SHA256SUMS )
    cp packaging/allowed_signers dist/allowed_signers
    ssh-keygen -Y sign -f "$SIGN_KEY" -n file dist/SHA256SUMS
    ssh-keygen -Y verify -f dist/allowed_signers -n file \
        -s dist/SHA256SUMS.sig -I vallum-release < dist/SHA256SUMS >/dev/null \
        || fail "self-verification of dist/SHA256SUMS.sig failed"
    ok "SHA256SUMS signed with $(ssh-keygen -lf "$SIGN_KEY" | awk '{print $2}')"

    ls -l dist
else
    echo "   would assemble dist/$name{,-aarch64}.tar.gz, the .deb, the .rpm,"
    echo "   dist/vallum-$tag-sbom.spdx.json, SHA256SUMS + SHA256SUMS.sig + allowed_signers"
fi

if [ "$UPLOAD" -eq 0 ]; then
    say "built (not uploaded)"
    exit 0
fi

say "publishing $tag"
if [ "$DRY" -eq 1 ]; then
    echo "   would create or update the GitHub release $tag with dist/*"
    exit 0
fi

if ! git rev-parse "$tag" >/dev/null 2>&1; then
    run git tag -a "$tag" -m "Vallum $tag"
fi
run git push origin "$tag"

# Release notes: the CHANGELOG section for this version, plus the verified
# install line and the signing key fingerprint that authenticates the assets.
fingerprint=$(ssh-keygen -lf "$SIGN_KEY" 2>/dev/null | awk '{print $2}')
{
    awk -v v="$version" '
        $0 ~ "^## " v "([^0-9]|$)" { f=1; next }
        /^## / && f { f=0 }
        f' CHANGELOG.md
    printf '\n## Install\n\n```sh\ncurl -fsSL -o /tmp/vallum-install.sh https://raw.githubusercontent.com/%s/main/scripts/install.sh\nsudo bash /tmp/vallum-install.sh --from-release %s\n```\n' "$REPO" "$tag"
    printf '\nAssets are SSH-signed (`SHA256SUMS.sig` + `allowed_signers`); install.sh verifies them. Signing key fingerprint: `%s`\n' "$fingerprint"
} > /tmp/vallum-release-notes.md

if gh release view "$tag" --repo "$REPO" >/dev/null 2>&1; then
    run gh release upload "$tag" dist/* --repo "$REPO" --clobber
    run gh release edit "$tag" --repo "$REPO" --notes-file /tmp/vallum-release-notes.md
else
    run gh release create "$tag" dist/* --repo "$REPO" \
        --title "Vallum $tag" \
        --notes-file /tmp/vallum-release-notes.md
fi
say "published $tag"
