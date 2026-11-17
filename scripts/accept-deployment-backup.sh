#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Gate: a deployment can be copied, verified and restored.
#
# `scripts/verify-remote.sh --clean-remote` deletes a live deployment before it
# installs its own, and it now refuses unless `scripts/backup-deployment.sh`
# succeeded against that host. A safety mechanism nobody has executed is a
# sentence, so this gate executes it: it builds a fake deployment (a config, a
# 0600 key, a unit, a SQLite account database), backs it up, restores it, and
# compares the result byte for byte.
#
# The failure paths matter as much as the happy one, because each would be
# silent in production:
#
#   * no deployment at all must exit 2, not "succeed" with an empty archive;
#   * a desk database that is not SQLite must fail, not be copied and trusted;
#   * an unusable destination must fail rather than skip the backup and go on;
#   * no archive is left behind by a failed run, so a later "it exited nonzero
#     but the file is there" cannot pass for a backup.
#
# No root, no network, no daemon: a temporary root and stdlib Python.
#
#   scripts/accept-deployment-backup.sh
#
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
trap 'rc=$?; command -v cleanup >/dev/null 2>&1 && cleanup; "$REPO/scripts/verdict.sh" accept-deployment-backup "$([ "$rc" -eq 0 ] && echo passed || echo failed)" "${ASSERTIONS:-0}" "$0"' EXIT
ASSERTIONS=0

say() { echo "[deploy-backup] $*"; }
die() { echo "[deploy-backup] FAIL: $*" >&2; exit 1; }
ok()  { ASSERTIONS=$((ASSERTIONS+1)); printf '   ok    %s\n' "$*"; }

WORK=$(mktemp -d -t vallum-deploy-backup.XXXXXX)
cleanup() { rm -rf "$WORK"; }

BACKUP="$REPO/scripts/backup-deployment.sh"
[ -f "$BACKUP" ] || die "missing $BACKUP"

ROOT="$WORK/root"
DEST="$WORK/out"
say "building a fake deployment under $ROOT"
mkdir -p "$ROOT/etc/vallum" "$ROOT/var/lib/vallum" "$ROOT/etc/systemd/system"
printf '[interface]\nname = "vallum0"\n' > "$ROOT/etc/vallum/vallum0.toml"
printf 'interface-private-key\n' > "$ROOT/etc/vallum/vallum0.key"
chmod 0600 "$ROOT/etc/vallum/vallum0.key"
printf '[Service]\nDescription=stub\n' > "$ROOT/etc/systemd/system/vallum@.service"
python3 - "$ROOT/var/lib/vallum/desk.sqlite" <<'PY' || die "could not build the desk database"
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute("CREATE TABLE accounts (token TEXT)")
db.execute("INSERT INTO accounts VALUES ('tok-alpha')")
db.commit(); db.close()
PY
ok "fake deployment in place"

say "taking the backup"
"$BACKUP" --root "$ROOT" --dest "$DEST" --label gate >/dev/null 2>&1 \
    || die "the backup failed on a healthy deployment"
ok "the backup exits 0"

archive=$(find "$DEST" -name 'vallum-gate-*.tar.gz' | head -1)
[ -n "$archive" ] || die "no archive was written to $DEST"
ok "an archive exists: $(basename "$archive")"

mode=$(stat -c '%a' "$archive")
[ "$mode" = "600" ] || die "the archive is mode $mode, not 600 — it holds every private key"
ok "the archive is mode 0600"

listing=$(tar -tzf "$archive")
for member in etc/vallum/vallum0.toml etc/vallum/vallum0.key \
              var/lib/vallum/desk.sqlite etc/systemd/system/vallum@.service; do
    printf '%s\n' "$listing" | grep -qxF "$member" || die "the archive is missing $member"
done
ok "every expected member is in the archive"

say "restoring it and comparing"
mkdir -p "$WORK/restored"
tar -xzpf "$archive" -C "$WORK/restored" || die "the archive would not extract"
cmp -s "$ROOT/etc/vallum/vallum0.toml" "$WORK/restored/etc/vallum/vallum0.toml" \
    || die "the restored config differs"
ok "the config round-tripped byte for byte"
cmp -s "$ROOT/etc/vallum/vallum0.key" "$WORK/restored/etc/vallum/vallum0.key" \
    || die "the restored key differs"
ok "the key round-tripped byte for byte"

key_mode=$(stat -c '%a' "$WORK/restored/etc/vallum/vallum0.key")
[ "$key_mode" = "600" ] || die "the restored key is mode $key_mode, not 600"
ok "the restored key kept mode 0600"

rows=$(python3 - "$WORK/restored/var/lib/vallum/desk.sqlite" <<'PY'
import sqlite3, sys
print(sqlite3.connect(sys.argv[1]).execute("SELECT count(*) FROM accounts").fetchone()[0])
PY
) || die "the restored desk database will not open"
[ "$rows" = "1" ] || die "the restored desk database has $rows accounts, expected 1"
ok "the restored desk database opens and holds its row"

say "the failure paths"
mkdir -p "$WORK/empty"
rc=0; "$BACKUP" --root "$WORK/empty" --dest "$WORK/out2" >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || die "no deployment exited $rc, expected 2"
[ -z "$(find "$WORK/out2" -name '*.tar.gz' 2>/dev/null)" ] || die "a failed run left an archive behind"
ok "no deployment exits 2 and writes nothing"

printf 'not a database\n' > "$ROOT/var/lib/vallum/desk.sqlite"
rc=0; "$BACKUP" --root "$ROOT" --dest "$WORK/out3" >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || die "a corrupt desk database exited $rc, expected 1"
[ -z "$(find "$WORK/out3" -name '*.tar.gz' 2>/dev/null)" ] || die "a corrupt copy was left behind"
ok "a corrupt desk database fails and writes nothing"

: > "$WORK/not-a-dir"
rc=0; "$BACKUP" --root "$ROOT" --dest "$WORK/not-a-dir" >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || die "an unusable destination exited $rc, expected 1"
ok "an unusable destination fails"

say "all $ASSERTIONS assertions passed"
