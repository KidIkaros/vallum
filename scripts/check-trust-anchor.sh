#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The release trust anchor is one *set* of keys in three places, and nothing
# checked that until this gate existed:
#
#   scripts/install.sh            RELEASE_SIGNING_PUBKEY   (embedded; what every
#                                                           user's installer verifies against)
#   packaging/vallum-release.pub  the committed public half  (what release.sh
#                                                           and the docs call the anchor)
#   packaging/allowed_signers     the ssh-keygen allowed_signers lines (what
#                                                           release.sh uses to verify
#                                                           verdict signatures and
#                                                           the packaged SHA256SUMS)
#
# A key rotation that updates two of the three leaves the third pinning the old
# key, and install.sh is the copy that matters most: it writes allowed_signers
# from its embedded list and then verifies the release's SHA256SUMS signature,
# failing hard. A stale embedded key therefore makes every fresh install refuse
# every release — on the day the project most needs installs to work. Nothing in
# the delivery path would catch that, because release.sh compares the *signing*
# key with vallum-release.pub and never reads install.sh.
#
# During a rotation the three files legitimately hold two keys — the outgoing and
# the incoming — so the comparison is between sets, not first keys. The set must
# agree; the order does not.
#
#   scripts/check-trust-anchor.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

# Key material only: `<principal> ssh-ed25519 <base64>` reduces to
# `ssh-ed25519 <base64>`, because the principal placement and the trailing
# comment differ between the three forms.
keys_from() { sed -n 's/.*\(ssh-ed25519 [A-Za-z0-9+/=]*\).*/\1/p' | sort -u; }

# install.sh: only the RELEASE_SIGNING_PUBKEY assignment. Its value may span
# lines — that is the rotation mechanism — so the region is the assignment
# itself, starting at the line that opens it and ending at the line whose value
# closes with a quote.
installer=$(awk '/^RELEASE_SIGNING_PUBKEY="/ { inside = 1 }
                 inside { print }
                 inside && /[^=]"[[:space:]]*$/ { inside = 0 }' scripts/install.sh | keys_from)

pub=$(keys_from < packaging/vallum-release.pub)
signers=$(keys_from < packaging/allowed_signers)

status=0
report() { # $1 = file, $2 = keys
    if [ -z "$2" ]; then
        printf '   MISS  %s carries no ssh-ed25519 key\n' "$1" >&2
        status=1
    else
        printf '   ok    %-32s %s key(s)\n' "$1" "$(printf '%s\n' "$2" | grep -c .)"
    fi
}
report scripts/install.sh "$installer"
report packaging/vallum-release.pub "$pub"
report packaging/allowed_signers "$signers"

if command -v ssh-keygen >/dev/null 2>&1 && [ -n "$pub" ]; then
    while IFS= read -r key; do
        [ -n "$key" ] || continue
        printf '   note  anchor key %s\n' \
            "$(printf '%s\n' "$key" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}')"
    done <<EOF
$pub
EOF
fi

if [ "$installer" != "$pub" ] || [ "$pub" != "$signers" ]; then
    cat >&2 <<'EOF'

The trust anchor disagrees across files. install.sh is the copy that decides what
every user's installer accepts, so it must change in the *same* commit as the
committed public half — and allowed_signers with it. A rotation that misses
install.sh makes every fresh install refuse the next release.

Rewrite all three from the public keys the releases will be signed with. During
a rotation keep BOTH — the outgoing key until a release has shipped signed only
by the incoming one:

    old=$(cut -d' ' -f1-2 ~/.config/vallum/release-signing-key.pub)
    new=$(cut -d' ' -f1-2 ~/.config/vallum/release-signing-key-new.pub)

    printf '%s vallum-release\n%s vallum-release\n' "$old" "$new" > packaging/vallum-release.pub
    printf 'vallum-release %s\nvallum-release %s\n'   "$old" "$new" > packaging/allowed_signers

    python3 - "$old" "$new" <<'PY'
    import pathlib, re, sys
    old, new = sys.argv[1], sys.argv[2]
    path = pathlib.Path("scripts/install.sh")
    text = path.read_text()
    pinned = 'RELEASE_SIGNING_PUBKEY="vallum-release %s\\nvallum-release %s"' % (old, new)
    path.write_text(re.sub(r'RELEASE_SIGNING_PUBKEY="[^"]*"', pinned, text, count=1))
    PY

Then run this gate again — and read "Break glass: the signing key" in
docs/releasing.md for what a rotation owes its users.
EOF
    status=1
elif [ "$status" -eq 0 ]; then
    count=$(printf '%s\n' "$pub" | grep -c .)
    if [ "$count" -eq 1 ]; then
        echo "ok — the anchor is one key in three places"
    else
        echo "ok — the anchor is the same $count keys in three places (a rotation is in progress)"
    fi
fi

exit "$status"
