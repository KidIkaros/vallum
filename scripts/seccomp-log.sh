#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# What would the filter have killed?
#
# ADR-0028 step 3. `interface.seccomp = "log"` installs the same filter as
# `enforce`, but the kernel answers a default-action match with a `SECCOMP` audit
# record — type 1326 — instead of a kill. The record names the program, the pid
# and the syscall *number*; it never names the syscall. This script is the
# collector: it reads those records back and reports the syscalls a deployment
# would have died on, so the list can be fixed from evidence rather than from
# another guess.
#
# Two properties matter more than the report:
#
#   1. **An empty report is not a clean one.** Records only exist if the kernel
#      auditing subsystem is enabled and something is reading it. If auditing is
#      off, or the log is unreadable, or there is no log at all, this says which
#      of those it is and exits 2. It never prints "none" for "did not look".
#   2. **It says what it could not resolve.** With `ausearch` (the `audit`
#      package) a record's syscall number is named; without it the number is
#      printed as a number. A syscall the allow-list omits has no name in this
#      binary either, so the number is the honest fallback, not a bug.
#
# Where the records come from: `auditd` writes them to
# `/var/log/audit/audit.log`. `docs/proof/seccomp.md` §5.1 explains why a
# production run, not a test, is what makes this useful.
#
# Usage:
#   sudo scripts/seccomp-log.sh                       # the default log
#   sudo scripts/seccomp-log.sh /var/log/audit/audit.log.1
#   sudo SECCOMP_COMM=vallum scripts/seccomp-log.sh   # a renamed daemon
#        SECCOMP_COMM=other scripts/seccomp-log.sh    # filter the comm
#
# Exit status:
#   0  read the log and found no would-kill record for that program
#   1  read the log and found at least one — the list is wrong for this run
#   2  could not read an audit source at all; nothing was concluded
#
# Requires nothing but `grep`/`awk`. `ausearch` is used when present, for names.

set -uo pipefail

COMM=${SECCOMP_COMM:-vallum}
FILE=${1:-${SECCOMP_AUDIT_LOG:-/var/log/audit/audit.log}}

cannot() {
    echo "seccomp-log: $*" >&2
    echo "seccomp-log: nothing was concluded about the allow-list" >&2
    exit 2
}

[ -e "$FILE" ] || cannot "no audit log at '$FILE': the kernel auditing subsystem writes none, so a run made without one leaves no record of what it would have killed (install and enable auditd, then re-run this against its log)"
[ -r "$FILE" ] || cannot "cannot read '$FILE': it is root-only (run under sudo) or it belongs to a group this user is not in"
command -v grep > /dev/null 2>&1 || cannot "missing 'grep'"
command -v awk > /dev/null 2>&1 || cannot "missing 'awk'"

# Auditing can be installed and still be off; the records are then dropped, and a
# log that has not been written since the run would look exactly like a clean one.
if command -v auditctl > /dev/null 2>&1; then
    state=$(auditctl -s 2> /dev/null | sed -n 's/^enabled[[:space:]]*//p')
    case "$state" in
        1 | 2) ;;
        *) cannot "kernel auditing is disabled (auditctl -s reports 'enabled ${state:-unknown}'): SECCOMP records are being dropped, so this log cannot answer the question (systemctl enable --now auditd)" ;;
    esac
fi

# One audit line per would-kill. `type=SECCOMP` is the name the kernel's own
# formatter uses; `type=1326` is the number, and some kernel versions print only
# that. Both are matched.
mine=$(mktemp) || cannot "cannot create a temporary file"
trap 'rm -f "$mine"' EXIT
grep -hE 'type=(SECCOMP|1326)\b' "$FILE" 2> /dev/null | grep -F "comm=\"$COMM\"" > "$mine"
total=$(wc -l < "$mine")

if [ "$total" = 0 ]; then
    records=$(grep -cE 'type=(SECCOMP|1326)\b' "$FILE" 2> /dev/null || true)
    echo "== no would-kill record for comm=\"$COMM\" in $FILE"
    echo "   $records SECCOMP record(s) in this file belong to other programs;"
    if [ "${records:-0}" = 0 ]; then
        echo "   there are none at all, so either nothing was filtered in this window"
        echo "   or the log covers a window in which the daemon did not run."
    fi
    exit 0
fi

# The kernel prints the syscall number; `ausearch -i` is what turns it into a
# name, and the fallback below says so instead of inventing one.
names=
if command -v ausearch > /dev/null 2>&1; then
    names=$(ausearch -if "$mine" -i -m SECCOMP 2> /dev/null) || names=
fi

echo "== $total would-kill record(s) for comm=\"$COMM\" in $FILE"
echo
if [ -n "$names" ]; then
    printf '%s\n' "$names" \
        | sed -n 's/.*syscall=\([^ ]*\).*/\1/p' \
        | sort | uniq -c | sort -rn \
        | awk '{ printf "   %-6s %s\n", $1, $2 }'
    echo
    echo "   Every name above is a syscall the allow-list does not name: in enforce"
    echo "   mode the daemon dies on the first one. Add it to ALLOWED in"
    echo "   crates/vallum/src/sandbox.rs, or stop making the call."
else
    sed -n 's/.*syscall=\([0-9][0-9]*\).*/\1/p' "$mine" \
        | sort | uniq -c | sort -rn \
        | awk '{ printf "   %-6s syscall %s\n", $1, $2 }'
    echo
    echo "   Those are syscall numbers, not names: the audit package's \`ausearch\`"
    echo "   translates them, and it is not installed. The numbers above are the"
    echo "   syscall a run in enforce mode would have died on."
fi

echo
echo "   First and last record, which is the window this can speak for:"
sed -n 's/.*audit(\([0-9.]*\).*/\1/p' "$mine" | sort -n | sed -n '1p;$p' | uniq \
    | while read -r at; do date -d "@${at%%.*}" '+     %Y-%m-%d %H:%M:%S'; done
exit 1
