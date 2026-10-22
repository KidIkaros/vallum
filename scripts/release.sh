#!/usr/bin/env bash
#
# Build and publish a release from this checkout.
#
# Hosted GitHub Actions is unavailable on this plan, so this script is the
# release pipeline: it builds the binaries, the .deb and .rpm, the tarball, and
# SHA256SUMS, then uploads them with `gh`.
#
#   scripts/release.sh                 # build, then create or update the release
#   scripts/release.sh --no-upload     # build into dist/ and stop
#   scripts/release.sh --dry-run       # print what would be built and uploaded
#   scripts/release.sh --skip-remote "why"   # release without a recent two-host run
#   scripts/release.sh --skip-arm "why"      # release without an aarch64 artifact
#   scripts/release.sh --skip-attestation "why"  # release without the signed release.json
#
# Releases are signed with an SSH key (`ssh-keygen -Y sign`, OpenSSH >= 8.0):
# the private key lives at ~/.config/vallum/release-signing-key (or
# $VALLUM_RELEASE_KEY) and the public half is committed at
# packaging/vallum-release.pub — the repository is the trust anchor, and
# install.sh verifies SHA256SUMS.sig before trusting any checksum.
#
# SHA256SUMS is additionally covered by a hybrid post-quantum attestation:
# `origin-provenance release-create` writes dist/release.json (Ed25519 +
# Falcon-1024 over the artifact set, product, channel, monotonic sequence and
# expiry) and release.json is listed in SHA256SUMS, so the SSH signature
# authenticates it too. install.sh verifies it with `origin-provenance
# release-verify` where that tool is available.
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
SKIP_ATTEST=""
SIGN_KEY="${VALLUM_RELEASE_KEY:-$HOME/.config/vallum/release-signing-key}"
ATTEST_KEY="${VALLUM_ATTEST_SEED:-$HOME/.config/vallum/release-attest.seed}"
ATTEST_FP_FILE="packaging/vallum-release-attest.fp"
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
        --skip-attestation)
            shift
            SKIP_ATTEST="${1:-}"
            [ -n "$SKIP_ATTEST" ] || { echo "--skip-attestation needs a reason" >&2; exit 1; }
            ;;
        -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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

# Monotonic release sequence derived from semver: 1.6.2 -> 1006002. The
# manifest carries it, the verifier compares it, so a replayed older release
# is refused rather than installed. `10#` keeps a zero-padded component from
# being read as octal.
attest_sequence() {
    local major minor patch
    IFS=. read -r major minor patch <<<"$1"
    echo $(( 10#${major:-0} * 1000000 + 10#${minor:-0} * 1000 + 10#${patch:-0} ))
}

# ── Preflight ────────────────────────────────────────────────────────────
# Every check here exists because it has already gone wrong once.
fail() {
    printf '   FAIL  %s\n' "$*" >&2
    echo "refusing to release" >&2
    exit 1
}
ok() { printf '   ok    %s\n' "$*"; }

say "preflight"

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

# The attestation seed (a raw 32-byte file) and the tool that signs with it.
# Same trust-anchor shape as the SSH key: the public half is a committed
# fingerprint, so a manifest signed by any other key is refused.
if [ -n "$SKIP_ATTEST" ]; then
    printf '   skip  release attestation: %s\n' "$SKIP_ATTEST"
elif [ "$DRY" -eq 0 ]; then
    [ -f "$ATTEST_KEY" ] || fail "no attestation seed at $ATTEST_KEY.
   Generate one:  head -c 32 /dev/urandom > \"$ATTEST_KEY\" && chmod 600 \"$ATTEST_KEY\"
   Then pin it:  release once, commit the fingerprint the run prints as $ATTEST_FP_FILE"
    command -v origin-provenance >/dev/null \
        || fail "origin-provenance is not on PATH.
   Build it:  (cd ../origin-tools && cargo build --release -p origin-provenance)
   Or release anyway with: --skip-attestation \"reason\""
    ok "attestation seed present, origin-provenance on PATH"
else
    echo "   would check $ATTEST_KEY and origin-provenance"
fi

if [ "$DRY" -eq 1 ]; then
    echo "   would run: E2E=1 ./scripts/verify.sh"
else
    say "gate: E2E"
    E2E=1 ./scripts/verify.sh >/tmp/vallum-release-gate.log 2>&1 \
        || { tail -20 /tmp/vallum-release-gate.log >&2; fail "scripts/verify.sh failed (see /tmp/vallum-release-gate.log)"; }
    ok "scripts/verify.sh passed"
fi

say "building"
run cargo build --release -p vallum -p vallum-quick

if [ "$DRY" -eq 0 ]; then
    # Stale completions once shipped a `teardown` nobody could tab-complete.
    # The packaged file must be the file this binary generates.
    for shell in bash zsh fish; do
        ./target/release/vallum completions "$shell" > /tmp/vallum-completions-check
        diff -q /tmp/vallum-completions-check "packaging/vallum.$shell" >/dev/null \
            || fail "packaging/vallum.$shell is stale — regenerate: vallum completions $shell > packaging/vallum.$shell"
    done
    ok "shell completions match this binary"
fi

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

say "packaging"
# Completions are generated from the binary, not committed: a stale copy
# advertises flags the binary no longer has, and the manifest check compares
# filenames so it cannot catch that. Generate before cargo-deb reads the asset
# table.
run scripts/gen-completions.sh
run rm -rf target/debian crates/vallum/target/generate-rpm dist
run cargo deb -p vallum --no-build
run bash -c "cd crates/vallum && cargo generate-rpm"

assemble() {
    local bindir=$1 name=$2
    mkdir -p "dist/$name"
    cp "$bindir/vallum" "$bindir/vallum-quick" "dist/$name/"
    cp LICENSE README.md "dist/$name/"
    cp packaging/vallum.8 packaging/vallum-quick.8 packaging/vallum.toml.5 "dist/$name/"
    cp packaging/vallum.bash packaging/vallum.zsh packaging/vallum.fish "dist/$name/"
    cp packaging/vallum@.service packaging/vallum-quick@.service \
        packaging/vallum-quick-watch@.service \
        packaging/vallum-enroll@.service packaging/vallum-metrics.service \
        packaging/vallum-metrics.timer packaging/vallum-alerts.yml "dist/$name/"
    tar -C dist -czf "dist/$name.tar.gz" "$name"
    rm -rf "dist/$name"
    # Inspect what we are about to publish. A release once shipped a tarball
    # without the enrolment unit because a copy line had been edited in the
    # wrong place; nobody noticed until it was installed on a host.
    # grep -c reads the whole listing; `grep -q` would exit on the first
    # match, tar would die on SIGPIPE, and pipefail would turn a present
    # member into a false failure.
    for member in vallum vallum-quick vallum@.service vallum-quick@.service \
        vallum-quick-watch@.service \
        vallum-enroll@.service vallum-metrics.service vallum-metrics.timer \
        vallum-alerts.yml vallum.8 vallum-quick.8 vallum.toml.5; do
        [ "$(tar -tzf "dist/$name.tar.gz" | grep -xc "$name/$member")" -ge 1 ] \
            || fail "the tarball is missing $member"
    done
}

# Hybrid post-quantum attestation of the artifact set. release.json is listed
# in SHA256SUMS, so the SSH signature authenticates it too — and its Falcon
# signature is what a verifier can check without trusting the transport at all.
#
# The verify step below is a round-trip health check on the REAL artifact set,
# not a tamper detector: release-create re-signs whatever bytes are in dist/,
# so a match is expected. What it proves is that `release-verify` accepts what
# `release-create` just produced — a broken format, an unreadable artifact or a
# tool/CLI drift fails here instead of on a user's host.
attest_artifacts() {
    local arts=() f fp pinned count=0
    for f in dist/*.tar.gz dist/*.deb dist/*.rpm; do
        if [ -f "$f" ]; then
            arts+=(--artifact "$f")
            count=$((count + 1))
        fi
    done
    [ "$count" -gt 0 ] || fail "no artifacts to attest"

    origin-provenance release-create \
        --product vallum --channel stable \
        --sequence "$(attest_sequence "$version")" \
        "${arts[@]}" \
        --seed-file "$ATTEST_KEY" \
        --output dist/release.json \
        || fail "origin-provenance release-create failed"

    origin-provenance release-verify dist/release.json --artifact-dir dist \
        --product vallum --channel stable \
        || fail "release-verify rejected the manifest release-create just produced — fix the tool before signing"

    fp=$(sed -n 's/.*"signer_fingerprint": *"\([0-9a-f]\{64\}\)".*/\1/p' dist/release.json | head -1)
    [ -n "$fp" ] || fail "could not read the attestation fingerprint from dist/release.json"
    if [ -f "$ATTEST_FP_FILE" ]; then
        pinned=$(tr -d '[:space:]' < "$ATTEST_FP_FILE")
        [ "$fp" = "$pinned" ] \
            || fail "$ATTEST_KEY derives $fp but $ATTEST_FP_FILE pins $pinned — sign with the pinned key or update the trust anchor"
        ok "attestation signer matches $ATTEST_FP_FILE"
    else
        printf '   warn  %s is missing; commit this fingerprint to pin the attestation key:\n' "$ATTEST_FP_FILE"
        printf '         %s\n' "$fp"
    fi
    ok "release.json attests $count artifacts (sequence $(attest_sequence "$version"))"
}

say "assembling the tarballs"
if [ "$DRY" -eq 0 ]; then
    assemble target/release "$name"
    [ -n "$SKIP_ARM" ] || assemble target/aarch64-unknown-linux-gnu/release "$name_arm"
    cp target/debian/*.deb dist/ 2>/dev/null || true
    cp crates/vallum/target/generate-rpm/*.rpm dist/ 2>/dev/null || true
    ok "the tarballs carry both binaries, all three units and the man pages"

    say "sbom"
    cargo sbom --output-format spdx_json_2_3 > "dist/vallum-$tag-sbom.spdx.json"
    ok "SBOM: dist/vallum-$tag-sbom.spdx.json (crates.io graph; the SDK is a git dependency)"

    say "attestation"
    if [ -n "$SKIP_ATTEST" ]; then
        printf '   skip  release attestation: %s\n' "$SKIP_ATTEST"
    else
        attest_artifacts
    fi

    say "signing"
    # release.json is hashed when it exists, so the SSH signature covers the
    # post-quantum attestation as well as the artifacts it lists. Written as an
    # if, not `[ -f ] && set --`: a failed test would end the subshell and
    # trip `set -e`.
    (
        cd dist
        set -- *.deb *.rpm *.tar.gz
        if [ -f release.json ]; then
            set -- "$@" release.json
        fi
        sha256sum "$@" > SHA256SUMS
    )
    cp packaging/allowed_signers dist/allowed_signers
    ssh-keygen -Y sign -f "$SIGN_KEY" -n file dist/SHA256SUMS
    ssh-keygen -Y verify -f dist/allowed_signers -n file \
        -s dist/SHA256SUMS.sig -I vallum-release < dist/SHA256SUMS >/dev/null \
        || fail "self-verification of dist/SHA256SUMS.sig failed"
    ok "SHA256SUMS signed with $(ssh-keygen -lf "$SIGN_KEY" | awk '{print $2}')"

    ls -l dist
else
    echo "   would assemble dist/$name{,-aarch64}.tar.gz, the .deb, the .rpm,"
    echo "   dist/vallum-$tag-sbom.spdx.json, dist/release.json (PQ attestation),"
    echo "   SHA256SUMS + SHA256SUMS.sig + allowed_signers"
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
    printf '\n## Install\n\n```sh\ncurl -fsSL https://raw.githubusercontent.com/%s/main/scripts/install.sh | sudo bash -s -- --from-release %s\n```\n' "$REPO" "$tag"
    printf '\nAssets are SSH-signed (`SHA256SUMS.sig` + `allowed_signers`); install.sh verifies them. Signing key fingerprint: `%s`\n' "$fingerprint"
    if [ -z "$SKIP_ATTEST" ]; then
        printf '\n`release.json` carries a hybrid Ed25519+Falcon-1024 attestation over the artifact set, product, channel and release sequence. Verify it yourself:\n\n```sh\norigin-provenance release-verify release.json --artifact-dir . --product vallum --channel stable\n```\n'
    fi
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
