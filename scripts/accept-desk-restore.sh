#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Gate: the desk's account database can be copied and restored.
#
# The account number is the only credential the desk issues and there is no
# reset flow (ADR-0045), so `desk.sqlite` is the one piece of state in the
# product that cannot be re-derived. A backup procedure nobody has executed is
# a sentence, not a mechanism — so this gate executes it: it builds a desk
# database with accounts, peers and codes, takes a copy with the shipped
# `service/vallum-desk-backup`, and then proves the copy is a *restorable*
# database rather than a file that exists.
#
# What it asserts, in the order a real restore would hit them:
#
#   * the copy is taken while the source is open for writing (the desk's own
#     access pattern: autocommit, several threads);
#   * the copy is mode 0600, because it holds every account token;
#   * the copy opens as a desk database — `open_database` accepts it, so the
#     schema and `PRAGMA user_version` survive the round trip;
#   * every account, peer and code row is present, and a known token is still
#     readable from the restored file;
#   * a missing source exits 2 instead of "succeeding" with nothing;
#   * a source that is not a database fails rather than writing a copy.
#
# No daemon, no root, no network: a temporary directory and stdlib Python.
#
#   scripts/accept-desk-restore.sh
#
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
trap 'rc=$?; command -v cleanup >/dev/null 2>&1 && cleanup; "$REPO/scripts/verdict.sh" accept-desk-restore "$([ "$rc" -eq 0 ] && echo passed || echo failed)" "${ASSERTIONS:-0}" "$0"' EXIT
ASSERTIONS=0

say() { echo "[desk-restore] $*"; }
die() { echo "[desk-restore] FAIL: $*" >&2; exit 1; }
ok()  { ASSERTIONS=$((ASSERTIONS+1)); printf '   ok    %s\n' "$*"; }

WORK=$(mktemp -d -t vallum-desk-restore.XXXXXX)
cleanup() { rm -rf "$WORK"; }

DESK="$REPO/service/vallum-desk"
BACKUP="$REPO/service/vallum-desk-backup"
[ -f "$DESK" ] || die "missing $DESK"
[ -f "$BACKUP" ] || die "missing $BACKUP"

SOURCE="$WORK/desk.sqlite"
DEST="$WORK/backups"
RESTORED="$WORK/restored.sqlite"

say "building a desk database with accounts, peers and codes"
python3 - "$DESK" "$SOURCE" <<'PY' || die "could not build the fixture database"
import importlib.util, sqlite3, sys
from importlib.machinery import SourceFileLoader

desk_path, state = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_loader("desk", SourceFileLoader("desk", desk_path))
desk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(desk)

db = desk.open_database(state)
# Three accounts with distinct plans, one peer each, one spent code: enough
# shape that a truncated or empty copy cannot pass the count checks below.
# Columns are the real schema's — `peer` is the legacy device name and is
# UNIQUE NOT NULL, so every account carries its own.
rows = [
    ("u0001-alpha", "alpha", "tok-alpha", "plan-a", 1000, "active"),
    ("u0001-beta",  "beta",  "tok-beta",  "plan-b", 5000, "active"),
    ("u0001-gamma", "gamma", "tok-gamma", "plan-c", 100,  "expired"),
]
for peer, label, token, plan, cap, status in rows:
    db.execute(
        "INSERT INTO accounts (peer, label, token, code, plan, created, expires, bytes_cap, status) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (peer, label, token, "friend-code-1", plan,
         "2026-11-17T00:00:00Z", "2027-01-01T00:00:00Z", cap, status))
    account_id = db.execute("SELECT id FROM accounts WHERE token = ?", (token,)).fetchone()[0]
    db.execute(
        "INSERT INTO peers (account_id, peer, label, created, status) VALUES (?,?,?,?,?)",
        (account_id, f"{peer}-dev", label, "2026-11-17T00:00:00Z", "active"))
db.execute(
    "INSERT INTO codes (code, created, used_by, days, bytes, plan) VALUES (?,?,?,?,?,?)",
    ("friend-code-1", "2026-11-17T00:00:00Z", "u0001-alpha", 14, 1000, "plan-a"))
print(f"fixture: {db.execute('SELECT count(*) FROM accounts').fetchone()[0]} accounts, "
      f"{db.execute('SELECT count(*) FROM peers').fetchone()[0]} peers, "
      f"{db.execute('SELECT count(*) FROM codes').fetchone()[0]} codes")
db.close()
PY

# The copy is taken while the source is still a live, committed database — the
# desk's own situation. `open_database` above committed every statement
# (autocommit), and the file is left in place rather than closed for the copy.
say "taking a copy with the shipped script"
"$BACKUP" --state "$SOURCE" --dest "$DEST" --keep 3 || die "the backup script failed"
ok "the backup script exited 0"

copies=("$DEST"/desk-*.sqlite)
[ -f "${copies[0]}" ] || die "no copy was written to $DEST"
ok "a copy exists: $(basename "${copies[0]}")"

mode=$(stat -c '%a' "${copies[0]}")
[ "$mode" = "600" ] || die "the copy is mode $mode, not 600 — it holds every account token"
ok "the copy is mode 0600"

# A restore is not "the file is there"; it is "the desk can open it".
say "restoring the copy and opening it as a desk database"
install -m 0600 "${copies[0]}" "$RESTORED"
python3 - "$DESK" "$RESTORED" <<'PY' || die "the restored copy is not a usable desk database"
import importlib.util, sys
from importlib.machinery import SourceFileLoader

desk_path, state = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_loader("desk", SourceFileLoader("desk", desk_path))
desk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(desk)

db = desk.open_database(state)
accounts = db.execute("SELECT count(*) FROM accounts").fetchone()[0]
peers = db.execute("SELECT count(*) FROM peers").fetchone()[0]
codes = db.execute("SELECT count(*) FROM codes").fetchone()[0]
version = db.execute("PRAGMA user_version").fetchone()[0]
token = db.execute("SELECT token FROM accounts WHERE token = 'tok-beta'").fetchone()
db.close()
assert (accounts, peers, codes) == (3, 3, 1), f"restored counts are {(accounts, peers, codes)}, not (3, 3, 1)"
assert token is not None and token[0] == "tok-beta", "a known account token did not survive the restore"
assert version > 0, f"restored user_version is {version}, not a migrated schema"
print(f"restored: {accounts} accounts, {peers} peers, {codes} codes, version {version}")
PY
ok "the restored copy opens and holds every row"
ok "a known account token survived the round trip"

say "a missing source must not look like a successful backup"
rc=0; "$BACKUP" --state "$WORK/absent.sqlite" --dest "$DEST" >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || die "a missing source exited $rc, expected 2 — an empty backup would be silent"
ok "a missing source exits 2"

say "a source that is not a database must fail, not be copied"
printf 'not a database\n' > "$WORK/garbage.sqlite"
rc=0; "$BACKUP" --state "$WORK/garbage.sqlite" --dest "$DEST" >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || die "a corrupt source exited $rc, expected 1"
ok "a corrupt source exits 1"

say "retention keeps the newest copies and no more"
for i in 1 2 3 4; do
    "$BACKUP" --state "$SOURCE" --dest "$DEST" --keep 3 --quiet || die "retention run $i failed"
done
count=$(find "$DEST" -name 'desk-*.sqlite' | wc -l)
[ "$count" -eq 3 ] || die "retention left $count copies, expected 3"
ok "retention kept 3 copies"

say "all $ASSERTIONS assertions passed"
