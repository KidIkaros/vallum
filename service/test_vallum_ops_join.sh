#!/bin/sh
# Pin the vallum-ops join stdin channels (#32, ADR-0046): line 1 ticket,
# line 2 token -> VALLUM_ACCOUNT, line 3 desk origin -> VALLUM_DESK_ENDPOINT.
# A mock vallum captures the env it receives, proving the dispatcher re-exports
# both across the (simulated) sudo boundary — the caller's env is NOT inherited
# by the mock for these two vars; only what the dispatcher sets from stdin.
# No real server or ticket redemption is needed.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OPS="$HERE/../packaging/vallum-ops"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# mock vallum: record the account/endpoint env and the stdin ticket it gets.
cat > "$TMP/vallum" <<'EOF'
#!/bin/sh
printf '%s' "${VALLUM_ACCOUNT:-}" > "$CAP_ACCOUNT"
printf '%s' "${VALLUM_DESK_ENDPOINT:-}" > "$CAP_DESK"
cat > "$CAP_STDIN"
EOF
chmod +x "$TMP/vallum"
export VALLUM_BIN="$TMP/vallum"
export CAP_ACCOUNT="$TMP/account" CAP_DESK="$TMP/desk" CAP_STDIN="$TMP/stdin"
# Ensure no inherited value can masquerade as a re-export.
unset VALLUM_ACCOUNT VALLUM_DESK_ENDPOINT 2>/dev/null || true

TOKEN=0123456789abcdef0123456789abcdef
TICKET=vallum1-join:203.0.113.7:51820:abcdef
fail=0
check() {
    if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: got '$1' want '$2'"; fail=1; fi
}

# Three lines: ticket + token + desk origin (the sudo-path join).
printf '%s\n%s\nhttps://desk.wingman.gold\n' "$TICKET" "$TOKEN" | "$OPS" join >/dev/null 2>&1
check "$(cat "$CAP_ACCOUNT")" "$TOKEN" "sudo-path join re-exports VALLUM_ACCOUNT (line 2)"
check "$(cat "$CAP_DESK")" "https://desk.wingman.gold" "sudo-path join re-exports VALLUM_DESK_ENDPOINT (line 3)"
check "$(cat "$CAP_STDIN")" "$TICKET" "the ticket rides stdin to vallum join"

# Two lines: ticket + token, no desk -> endpoint empty, token still sealed.
printf '%s\n%s\n' "$TICKET" "$TOKEN" | "$OPS" join >/dev/null 2>&1
check "$(cat "$CAP_ACCOUNT")" "$TOKEN" "two-line join still re-exports VALLUM_ACCOUNT"
check "$(cat "$CAP_DESK")" "" "no desk line -> empty VALLUM_DESK_ENDPOINT"

# One line: ticket only -> neither account nor endpoint.
printf '%s\n' "$TICKET" | "$OPS" join >/dev/null 2>&1
check "$(cat "$CAP_ACCOUNT")" "" "ticket-only join -> empty VALLUM_ACCOUNT"
check "$(cat "$CAP_DESK")" "" "ticket-only join -> empty VALLUM_DESK_ENDPOINT"

# A desk endpoint with shell metacharacters is refused (injection guard).
if printf '%s\n%s\nhttps://desk.example.com;touch %s/pwned\n' "$TICKET" "$TOKEN" "$TMP" | "$OPS" join >/dev/null 2>&1; then
    echo "FAIL a metacharacter desk endpoint should be refused"; fail=1
else
    echo "ok   a metacharacter desk endpoint is refused"
fi
[ -e "$TMP/pwned" ] && { echo "FAIL injection executed"; fail=1; }

if [ "$fail" = 0 ]; then echo "PASS test_vallum_ops_join (7 assertions)"; else echo "FAILED test_vallum_ops_join"; exit 1; fi
