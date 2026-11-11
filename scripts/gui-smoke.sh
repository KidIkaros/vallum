#!/usr/bin/env bash
#
# Walk the console's HTTP API end to end against a fake daemon socket.
#
#   ./scripts/gui-smoke.sh
#
# This is the check that the panel's buttons are wired to the same functions as
# the terminal: it drives `/api/cmd/*` exactly as the UI does, over real HTTP,
# with no surface to render. It needs no root and touches no tunnel — the
# daemon is a Unix socket answering the canned `get=1` reply below.
#
# What it covers: the bundle a peer scans (export → QR frames → import, with the
# key landed at 0600), a fresh key, an invite that must refuse without a public
# endpoint, an unknown command, and the write gate refusing a socket that other
# users can reach.
#
# It is not a substitute for `gui-cancel-gate.sh` (which needs real systemd) or
# for looking at the screen.
set -euo pipefail

root_dir=$(cd "$(dirname "$0")/.." && pwd)
cd "$root_dir"

GUI=${VALLUM_GUI:-target/debug/vallum-gui}
VALLUM=${VALLUM:-target/debug/vallum}
UI=crates/vallum-gui/ui/dist
PORT=${VALLUM_SMOKE_PORT:-7451}
WORK=$(mktemp -d /tmp/vallum-smoke.XXXXXX)
SOCK="$WORK/vallum0.sock"
CONFIG="$WORK/vallum0.toml"
RUNTIME="$WORK/run"
pids=()

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

cleanup() {
    for pid in "${pids[@]}"; do
        kill "$pid" >/dev/null 2>&1 || true
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$GUI" ] || fail "no $GUI — run: cargo build -p vallum-gui"
[ -x "$VALLUM" ] || fail "no $VALLUM — run: cargo build -p vallum"
[ -d "$UI" ] || fail "no $UI — run: (cd crates/vallum-gui/ui && npm run build)"

mkdir -p "$RUNTIME"
"$VALLUM" keygen --output "$WORK/private.key" >"$WORK/public.line" ||
    fail "keygen refused to mint the fixture key"
chmod 600 "$WORK/private.key"
PUBLIC=$(head -1 "$WORK/public.line")
[ -n "$PUBLIC" ] || fail "keygen printed no public line"

cat >"$CONFIG" <<EOF
[interface]
name = "vallum0"
private_key = "$WORK/private.key"
address = "10.9.0.1/24"
listen = "127.0.0.1:0"
control = "$SOCK"
EOF

# The fake daemon: one request per connection, the allowlisted reply, close.
# `vallum_public_line` is this fixture's own line so the export is a real one.
cat >"$WORK/daemon.py" <<'PY'
import os, socket, sys

path = sys.argv[1]
public = sys.argv[2]
reply = "\n".join([
    "vallum_interface=vallum0",
    "listen_port=51820",
    "fwmark=51820",
    "vallum_suite=0x0003",
    f"vallum_public_line={public}",
    "vallum_address=10.9.0.1/24",
    "errno=0",
    "",
    "public_key=cGVlci1wdWJsaWM=",
    "vallum_name=laptop",
    "vallum_fingerprint=ab:cd:ef:01",
    "endpoint=203.0.113.9:51820",
    "allowed_ip=10.9.0.2/32",
    "allowed_ip=fd00:9::2/128",
    "last_handshake_time_sec=1700000000",
    "tx_bytes=1024",
    "rx_bytes=2048",
    "vallum_epoch=3",
    "errno=0",
    "",
]) .encode()

try:
    os.unlink(path)
except FileNotFoundError:
    pass
sock = socket.socket(socket.AF_UNIX)
sock.bind(path)
os.chmod(path, 0o600)
sock.listen(8)
while True:
    conn, _ = sock.accept()
    with conn:
        try:
            conn.recv(4096)
            conn.sendall(reply)
        except OSError:
            pass
PY

python3 "$WORK/daemon.py" "$SOCK" "$PUBLIC" &
pids+=($!)
for _ in $(seq 1 50); do
    [ -S "$SOCK" ] && break
    sleep 0.1
done
[ -S "$SOCK" ] || fail "the fake daemon did not publish its socket"

VALLUM_RUNTIME_DIR="$RUNTIME" "$GUI" --serve "$PORT" >"$WORK/serve.log" 2>&1 &
pids+=($!)

api() {
    curl -sf -m 20 -X POST "http://127.0.0.1:$PORT$1" \
        -H "content-type: application/json" -d "${2:-{\}}"
}

# For the refusals: the body is the evidence, so the status must still fail the
# call without throwing the body away (`-f` would).
api_any() {
    curl -s -m 20 -X POST "http://127.0.0.1:$PORT$1" \
        -H "content-type: application/json" -d "${2:-{\}}"
}

for _ in $(seq 1 50); do
    api /api/select "{\"path\":\"$SOCK\"}" >/dev/null 2>&1 && break
    sleep 0.2
done
api /api/select "{\"path\":\"$SOCK\"}" >/dev/null 2>&1 ||
    fail "the console did not answer /api/select $(tail -2 "$WORK/serve.log")"
echo "== selected $SOCK"

# A tiny JSON accessor, so assertions read as assertions rather than jq trivia.
field() {
    python3 -c '
import json, sys
value = json.load(sys.stdin)
for key in sys.argv[1].split("."):
    value = value[int(key)] if isinstance(value, list) else value[key]
print(value if not isinstance(value, bool) else str(value).lower())
' "$1"
}

echo "== export: a bundle for the peer the daemon reports"
api /api/cmd/export_bundle \
    '{"fingerprint":"ab:cd:ef:01","endpoint":"203.0.113.5:51820"}' >"$WORK/bundle.out"
[ "$(field message <"$WORK/bundle.out")" != "" ] || fail "export returned no message"
field json <"$WORK/bundle.out" >"$WORK/client.vallum-bundle"
[ -s "$WORK/client.vallum-bundle" ] || fail "export returned an empty bundle"
echo "   $(wc -c <"$WORK/client.vallum-bundle") bytes for $(field filename <"$WORK/bundle.out")"

echo "== qr: the same text animates, frame by frame"
BUNDLE=$(cat "$WORK/client.vallum-bundle")
api /api/cmd/qr_frame "$(python3 -c '
import json, sys
print(json.dumps({"text": open(sys.argv[1]).read(), "index": 0}))
' "$WORK/client.vallum-bundle")" >"$WORK/frame0.out"
TOTAL=$(field total <"$WORK/frame0.out")
HASH=$(field hash <"$WORK/frame0.out")
[ "$TOTAL" -ge 1 ] || fail "the bundle encoded to no frames"
for index in $(seq 1 $((TOTAL - 1))); do
    api /api/cmd/qr_frame "$(python3 -c '
import json, sys
print(json.dumps({"text": open(sys.argv[1]).read(), "index": int(sys.argv[2])}))
' "$WORK/client.vallum-bundle" "$index")" >"$WORK/frame.out"
    [ "$(field hash <"$WORK/frame.out")" = "$HASH" ] ||
        fail "frame $index disagrees about the set hash"
done
echo "   $TOTAL frames, hash $HASH"

if api /api/cmd/qr_frame "{\"text\":\"$BUNDLE\",\"index\":$TOTAL}" >/dev/null 2>&1; then
    fail "a frame past the end was served"
fi
echo "   past-the-end frame refused"

echo "== import: the bundle becomes a config and a 0600 key"
mkdir -p "$WORK/imported"
api /api/cmd/import_bundle \
    "{\"bundlePath\":\"$WORK/client.vallum-bundle\",\"outDir\":\"$WORK/imported\"}" \
    >"$WORK/import.out"
IMPORTED_KEY=$(ls "$WORK"/imported/*.key 2>/dev/null | head -1)
[ -n "$IMPORTED_KEY" ] || fail "import wrote no key"
[ "$(stat -c %a "$IMPORTED_KEY")" = 600 ] || fail "imported key is not 0600"
ls "$WORK"/imported/*.toml >/dev/null 2>&1 || fail "import wrote no config"
echo "   $(field message <"$WORK/import.out")"

# Keygen mints into the reply rather than onto the disk: the key exists only in
# the download until the operator places it, which is the point of the flow.
echo "== keygen: a fresh key, in the reply and not on disk"
api /api/cmd/generate_key '{}' >"$WORK/key.out"
NEW_KEY_NAME=$(field filename <"$WORK/key.out")
[ "${NEW_KEY_NAME%.key}" != "$NEW_KEY_NAME" ] || fail "keygen returned no .key filename"
[ -n "$(field text <"$WORK/key.out")" ] || fail "keygen returned an empty key"
[ -e "$WORK/$NEW_KEY_NAME" ] && fail "keygen wrote the key to the working directory"
echo "   $NEW_KEY_NAME"

echo "== invite: refused while the config has no public endpoint"
if api /api/cmd/invite_peer '{"name":"phone","ttl_minutes":"","pinned":""}' \
    >/dev/null 2>&1; then
    fail "an invite was minted for a config with no public_endpoint"
fi
api_any /api/cmd/invite_peer '{"name":"phone","ttl_minutes":"","pinned":""}' \
    >"$WORK/invite.out"
grep -q public_endpoint "$WORK/invite.out" ||
    fail "the refusal does not name public_endpoint: $(cat "$WORK/invite.out")"
echo "   $(python3 -c '
import json, sys
print(json.load(open(sys.argv[1])).get("error", "").splitlines()[0])
' "$WORK/invite.out" 2>/dev/null || head -1 "$WORK/invite.err")"

echo "== unknown command: rejected, not silently accepted"
if api /api/cmd/not_a_command '{}' >/dev/null 2>&1; then
    fail "an unknown command was accepted"
fi
echo "   ok"

echo "== write gate: a socket others can reach refuses writes"
chmod 775 "$SOCK"
# The invite is a write that goes through `write_gate`: it mints a token into
# the daemon's runtime directory, which a socket others can reach does not
# authorise. `write_config` is not used here — it gates the config file's own
# permissions, not the socket's.
if api /api/cmd/invite_peer '{"name":"phone","ttl_minutes":"","pinned":""}' \
    >/dev/null 2>&1; then
    fail "a write ran against a 0775 control socket"
fi
api_any /api/cmd/invite_peer '{"name":"phone","ttl_minutes":"","pinned":""}' \
    >"$WORK/gate.out"
grep -q "0600" "$WORK/gate.out" || fail "the gate refusal does not name 0600"
echo "   $(head -c 140 "$WORK/gate.out")"
chmod 600 "$SOCK"

echo "PASS"
