#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The regression test for the worst defect the premortem's investigators found:
# the two-host gate could report PASS - and stamp the commit as verified -
# after failing to restore the production host's NAT table.
#
#   scripts/selftest-restore-fail.sh
#
# It exercises the same shape as scripts/verify-remote.sh's cleanup: a restore
# that fails must (1) say so, (2) exit non-zero, and (3) revoke the stamp. The
# real script is 1500 lines and destructive to run, so the logic under test is
# duplicated here EXACTLY as it appears there - if the two ever diverge, this
# test stops being a proof. That duplication is the price of testing a
# destructive script without destroying production.
set -uo pipefail

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

STAMP="$WORK/remote-verified"
NAT_SAVE="$WORK/nat.save"
printf 'table inet vallum {}\n' > "$NAT_SAVE"
printf 'deadbeef\n' > "$STAMP"

failures=0
check() {
    if [ "$2" = "$3" ]; then
        echo "   ok    $1"
    else
        echo "   FAIL  $1: expected '$3', got '$2'"
        failures=$((failures + 1))
    fi
}

# ---- the logic under test, copied from scripts/verify-remote.sh ----
NAT_RESTORE_FAILED=0
restore_nat() {
    [ -s "$NAT_SAVE" ] || return 0
    if rsh "sudo nft -f -" <"$NAT_SAVE" >/dev/null 2>&1; then
        ok "the host's own \`inet vallum\` NAT table was restored"
        return 0
    fi
    fail "the host's \`inet vallum\` NAT table could NOT be restored from $NAT_SAVE"
    fail "   the host's tunnel egress is broken until that table is put back:"
    fail "   sudo nft -f $NAT_SAVE"
    NAT_RESTORE_FAILED=1
    return 1
}

verified_stamp() {
    printf '%s' "$STAMP"
}

cleanup() {
    set +e
    restore_nat
    if [ "$NAT_RESTORE_FAILED" = 1 ]; then
        rm -f "$(verified_stamp)" 2>/dev/null
        fail "the commit was NOT recorded as verified: the host was left unrestored"
        exit 1
    fi
    ok "both ends restored"
}
# ---- end of the logic under test ----

say(){ printf '── %s\n' "$*"; }
ok(){ printf '   ok    %s\n' "$*"; }
fail(){ printf '   FAIL  %s\n' "$*"; }

echo "== the restore succeeds"
rsh() { return 0; }          # a restore that works
cleanup
check "the stamp survives a good restore" "$([ -f "$STAMP" ] && echo yes || echo no)" "yes"

echo
echo "== the restore fails"
printf 'deadbeef\n' > "$STAMP"
rsh() { return 1; }          # a restore that does not work
set +e
( cleanup )
rc=$?
set -e
check "the run fails" "$rc" "1"
check "the stamp is revoked" "$([ -f "$STAMP" ] && echo yes || echo no)" "no"

echo
if [ "$failures" -eq 0 ]; then
    echo "== PASS - a failed restore fails the run and revokes the stamp"
    exit 0
fi
echo "== FAIL - $failures check(s) failed"
exit 1
