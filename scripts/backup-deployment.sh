#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Take and verify a copy of a Vallum deployment before something deletes it.
#
# `scripts/verify-remote.sh --clean-remote` removes a live deployment so it can
# install its own: it stops the units, deletes /etc/vallum, the binaries, the
# sysctl file and the firewall rules. The restore used to be a tarball built by
# hand from a paragraph in the alpha-readiness document — so the gate that
# proves the product could destroy it whenever someone did not read that far.
#
# This script is the mechanism, and `verify-remote.sh` refuses to delete
# anything unless it succeeded. It takes the two roots that cannot be
# reinstalled — /etc/vallum (keys, configs, peers) and /var/lib/vallum (the
# desk's account database, whose account numbers cannot be re-issued) — plus
# the units and helpers when they are present, and then **verifies the
# archive**: every expected member is listed, every config file that existed is
# in it, and the desk database is not just present but still begins with the
# SQLite header.
#
#   sudo backup-deployment.sh                          # -> /root/vallum-pre-verify-remote-<stamp>.tar.gz
#   sudo backup-deployment.sh --dest /var/backups --label before-upgrade
#   backup-deployment.sh --root /tmp/fakeroot --dest /tmp/out   # for the gate
#
# Exit: 0 verified, 1 failed (no archive is left behind), 2 nothing to back up.
#
# The archive contains private keys, so it is written 0600 and the script says
# so. Restoring is `tar -xzpf <archive> -C /` as root, then `systemctl
# daemon-reload` — the same paths that were removed, so the same deployment
# comes back.
set -euo pipefail

ROOT=/
DEST=/root
LABEL=pre-verify-remote

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        --root)  ROOT=${2:-}; shift 2 || true ;;
        --dest)  DEST=${2:-}; shift 2 || true ;;
        --label) LABEL=${2:-}; shift 2 || true ;;
        -h|--help) usage; exit 0 ;;
        *) echo "backup-deployment: unknown argument: $1" >&2; exit 2 ;;
    esac
done

[ -n "$ROOT" ] && [ -n "$DEST" ] || { echo "backup-deployment: --root and --dest need a value" >&2; exit 2; }

# Trailing slashes make `tar -C` and the member names disagree.
root=${ROOT%/}
cd_root=${root:-/}

die() { echo "backup-deployment: $*" >&2; exit 1; }

if [ ! -d "$cd_root/etc/vallum" ]; then
    echo "backup-deployment: no $cd_root/etc/vallum — nothing to back up" >&2
    exit 2
fi

# What ships in the archive. Required roots first, then the pieces a package
# restores for you but a hand install does not.
members=(etc/vallum)
[ -d "$cd_root/var/lib/vallum" ] && members+=(var/lib/vallum)
for unit in "$cd_root"/etc/systemd/system/vallum* "$cd_root"/lib/systemd/system/vallum*; do
    [ -e "$unit" ] || continue
    members+=("${unit#"$cd_root"/}")
done
[ -e "$cd_root/usr/local/sbin/vallum-ops" ] && members+=(usr/local/sbin/vallum-ops)
[ -d "$cd_root/usr/local/lib/vallum" ] && members+=(usr/local/lib/vallum)

[ -d "$DEST" ] || mkdir -p "$DEST" || die "cannot create $DEST"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
archive="$DEST/vallum-$LABEL-$stamp.tar.gz"

# `-p` keeps the modes: the configs and keys are 0600 and must come back that
# way. The archive itself is 0600 too — it holds every private key on the host.
umask 077
tar -czpf "$archive" -C "$cd_root" "${members[@]}" || { rm -f "$archive"; die "tar failed"; }
chmod 0600 "$archive"

# ── verify the archive, not the tar invocation ────────────────────────────
listing=$(tar -tzf "$archive") || { rm -f "$archive"; die "the archive will not list"; }

# A member counts as present when the listing names it exactly, or names
# something inside it — `etc/vallum/` with no files under it is the case this
# must not accept, which is why the config loop below exists as well.
missing=""
for want in "${members[@]}"; do
    want=${want%/}
    printf '%s\n' "$listing" \
        | awk -v want="$want" 'index($0, want "/") == 1 || $0 == want { found = 1 } END { exit !found }' \
        || missing="$missing $want"
done
[ -z "$missing" ] || { rm -f "$archive"; die "the archive is missing:$missing"; }

# Every config that existed must be in it: a member-level check passes even if
# tar stored a directory and nothing inside it.
configs=0
while IFS= read -r -d '' toml; do
    configs=$((configs + 1))
    rel=${toml#"$cd_root"/}
    printf '%s\n' "$listing" | grep -qxF -- "$rel" \
        || { rm -f "$archive"; die "the archive is missing the config $rel"; }
done < <(find "$cd_root/etc/vallum" -maxdepth 1 -name '*.toml' -print0)

# The desk's database is the state that cannot be rebuilt: presence is not
# enough, it must still be a SQLite file.
desk=var/lib/vallum/desk.sqlite
if [ -f "$cd_root/$desk" ]; then
    printf '%s\n' "$listing" | grep -qxF -- "$desk" \
        || { rm -f "$archive"; die "the archive is missing $desk"; }
    header=$(tar -xzOf "$archive" "$desk" 2>/dev/null | head -c 15 || true)
    [ "$header" = "SQLite format 3" ] \
        || { rm -f "$archive"; die "$desk in the archive is not a SQLite database"; }
fi

size=$(du -h "$archive" | cut -f1)
sha=$(sha256sum "$archive" | cut -d' ' -f1)
echo "backup-deployment: $archive ($size, mode 0600)"
echo "   members:    $(printf '%s\n' "$listing" | wc -l) entries, $configs config(s)"
echo "   sha256:     $sha"
echo "   restore:    sudo tar -xzpf $archive -C / && sudo systemctl daemon-reload"
echo "   contains private keys — move it off this host or delete it once the run is done"
