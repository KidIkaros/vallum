set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
trap 'rc=$?; command -v cleanup >/dev/null 2>&1 && cleanup; "$REPO/scripts/verdict.sh" accept-connect-link "$([ "$rc" -eq 0 ] && echo passed || echo failed)" "${ASSERTIONS:-0}" "$0"' EXIT
ASSERTIONS=0

say() { echo "[connect-link] $*"; }
die() { echo "[connect-link] FAIL: $*" >&2; exit 1; }

say "building the release binary"
cargo build --release -p vallum >/dev/null 2>&1 || die "cargo build --release -p vallum failed"
[ -x "$REPO/target/release/vallum" ] || die "no binary after build"
cd "$REPO"
command -v unshare >/dev/null 2>&1 || die "unshare (util-linux) is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required (the desk + the API client)"

WORK=$(mktemp -d /tmp/vallum-connect-link.XXXXXX)
cleanup() { rm -rf -- "$WORK"; }

# The lab body is materialized to a seekable file (the e2e-netns suite documented
# a bash parser bug on non-seekable stdin heredocs above a certain size).
cat > "$WORK/inner.sh" <<'INNER'
set -u
BIN=$1
WORK=$2
REPO=$3
export PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH
FAIL=0
note() { printf '\n── %s\n' "$*"; }
ok()   { printf '   ok    %s\n' "$*"; }
bad()  { printf '   FAIL  %s\n' "$*" >&2; exit 1; }
check() { if [ "$1" = 0 ]; then ok "$2"; else printf '   FAIL  %s\n' "$2" >&2; FAIL=1; fi; }

mount -t tmpfs tmpfs /etc/vallum || exit 90
mount -t tmpfs tmpfs /run || exit 90
mkdir -p /run/vallum
ip link set lo up

LAB=$WORK
V=$BIN
DESK_PORT=8400

cleanup() {
    for f in "$LAB"/*.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done
    [ -n "${HOLDER:-}" ] && kill "$HOLDER" 2>/dev/null
    wait 2>/dev/null
    chmod -R a+rwX "$LAB" 2>/dev/null || true
}
trap cleanup EXIT

note "outer network: server (ns1) and client (ns2) joined by veth"
ip link add veth-a type veth peer name veth-b
ip link set veth-a up; ip addr add 10.99.0.1/24 dev veth-a
unshare -n sleep infinity & HOLDER=$!
sleep 0.3
ip link set veth-b netns "$HOLDER"
in_ns() { nsenter -t "$HOLDER" -n -- "$@"; }
in_ns ip link set lo up; in_ns ip link set veth-b up; in_ns ip addr add 10.99.0.2/24 dev veth-b
ping -c1 -W2 -q 10.99.0.2 >/dev/null 2>&1; check $? "outer network crosses (veth)"

note "server init (veth endpoint, enrolment on)"
"$V" server init --config /etc/vallum/srv.toml --address 10.77.0.1/24 \
    --listen 10.99.0.1:51990 --no-host --no-service --enroll > "$LAB/init.log" 2>&1
check $? "server init"
python3 - <<'EOF'
p = '/etc/vallum/srv.toml'
text = open(p).read()
text = text.replace('[interface]', '[interface]\npublic_endpoint = "10.99.0.1:51990"', 1)
open(p, 'w').write(text)
EOF
grep -q 'public_endpoint' /etc/vallum/srv.toml; check $? "public_endpoint set (a device can dial it)"

note "start the daemon + the enrolment responder (ns1)"
setsid "$V" run --config /etc/vallum/srv.toml >> "$LAB/srv.log" 2>&1 & echo $! > "$LAB/srv.pid"
setsid "$V" enroll-serve --config /etc/vallum/srv.toml >> "$LAB/enroll.log" 2>&1 & echo $! > "$LAB/enroll.pid"
sleep 2
"$V" show --config /etc/vallum/srv.toml --json > "$LAB/srv-show.json" 2>&1
check $? "server daemon answers on its control socket"

note "start the desk against the real daemon (ns1, loopback HTTP)"
printf 'cohort-code-7\n' > "$LAB/codes.txt"
printf 'lab-admin-token\n' > "$LAB/admin-token"
setsid python3 "$REPO/service/vallum-desk" \
    --config /etc/vallum/srv.toml --state "$LAB/desk.sqlite" \
    --codes "$LAB/codes.txt" --admin-token-file "$LAB/admin-token" \
    --bind 127.0.0.1 --port "$DESK_PORT" --cli "$V" \
    --trial-days 14 --trial-bytes 1000000000 --device-cap 5 \
    >> "$LAB/desk.log" 2>&1 & echo $! > "$LAB/desk.pid"
ready=1
for i in $(seq 1 50); do
    if python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:$DESK_PORT/healthz',timeout=2)" 2>/dev/null; then
        ready=0; break
    fi
    sleep 0.2
done
check $ready "desk /healthz answers"
[ $ready -eq 0 ] || { tail -20 "$LAB/desk.log" >&2; bad "the desk never came up"; }

cat > "$LAB/api.py" <<'EOF'
import sys, urllib.request, urllib.error
path, body = sys.argv[1], sys.argv[2]
req = urllib.request.Request("http://127.0.0.1:8400" + path, data=body.encode(),
                             headers={"Content-Type": "application/json"}, method="POST")
try:
    r = urllib.request.urlopen(req, timeout=20)
    sys.stdout.write(r.read().decode()); sys.exit(r.status)
except urllib.error.HTTPError as e:
    sys.stdout.write(e.read().decode()); sys.exit(e.code)
EOF
api() { python3 "$LAB/api.py" "$1" "$2"; }

# The client's PATH: the release binary and the shipped scheme handler. A
# sudo stub that always fails keeps _privileged_join_available() false —
# inside this namespace we are root, and the real dispatcher would invoke
# the host's /usr/bin/vallum, not the build under test. The stub makes the
# same-uid fallback deterministic, which is the path a machine without the
# dispatcher takes.
mkdir -p "$LAB/bin" "$LAB/home"
ln -s "$V" "$LAB/bin/vallum"
ln -s "$REPO/service/vallum-uri" "$LAB/bin/vallum-uri"
printf '#!/bin/sh\nexit 1\n' > "$LAB/bin/sudo"
chmod +x "$LAB/bin/sudo"
NS_ENV="PATH=$LAB/bin:/usr/bin:/bin HOME=$LAB/home"
ns_client() { in_ns env -u DISPLAY -u WAYLAND_DISPLAY $NS_ENV "$@"; }

note "COLLEAGUE step 1: account-only signup"
SIGNUP=$(api /api/signup '{"code":"cohort-code-7"}'); RC=$?
[ "$RC" = 200 ]; check $? "signup HTTP 200 (rc=$RC)"
TOKEN=$(printf '%s' "$SIGNUP" | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])' 2>/dev/null)
[ -n "$TOKEN" ]; check $? "signup returned an account token"

note "COLLEAGUE step 2: add a device — the desk mints the Connect link"
DEVICES=$(api /api/devices "$(python3 -c 'import json,sys;print(json.dumps({"token":sys.argv[1],"name":"laptop"}))' "$TOKEN")"); RC=$?
[ "$RC" = 200 ]; check $? "POST /api/devices HTTP 200 (rc=$RC)"
CONNECT=$(printf '%s' "$DEVICES" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("connect",""))' 2>/dev/null)
case "$CONNECT" in
    vallum://join\?ticket=*) : ;;
    *) CONNECT="" ;;
esac
[ -n "$CONNECT" ]; check $? "devices returned a vallum://join Connect link"
printf '%s' "$CONNECT" | grep -q 'desk=https'; check $? "the link carries the desk origin (ADR-0046)"

note "COLLEAGUE step 3: click the link — vallum-uri enrols (ns2, headless)"
# No DISPLAY: the handler cannot be drive-by-fired here — an operator or a
# script invoked it — so it proceeds without a dialog. sudo fails by stub,
# so this is the same-uid `vallum join -` fallback a dispatcher-less
# machine takes.
ns_client vallum-uri "$CONNECT" > "$LAB/uri-join.log" 2>&1; RC=$?
[ "$RC" = 0 ]; check $? "vallum-uri enrolled through the link (rc=$RC)"
grep -q 'enrolled' "$LAB/uri-join.log"; check $? "the join enrolled (log)"
CFG=$(ls /etc/vallum/*.toml 2>/dev/null | grep -v srv.toml | head -1)
[ -n "$CFG" ]; check $? "the join wrote a client config"
grep -q '^\[account\]' "$CFG" 2>/dev/null; check $? "the account token was sealed into the config (ADR-0046)"

note "run the tunnel (ns2) and prove it carries traffic"
if [ -n "$CFG" ]; then
    in_ns bash -c "setsid $V run --config $CFG >> $LAB/client.log 2>&1 & echo \$! > $LAB/client.pid"
    sleep 2
    in_ns ping -c3 -W2 10.77.0.1 > "$LAB/ping.log" 2>&1
    check $? "ping 10.77.0.1 rides the tunnel the link built"
fi

note "the sealed account answers the account verb against the real desk"
# The lab desk speaks plain HTTP on loopback — an endpoint form the
# account read explicitly permits off-HTTPS only on loopback. Production
# desks are https; here the sealed origin is flipped to the lab's scheme.
# And loopback is per-namespace: the desk listens in ns1, so the read
# runs there (in production it runs on the client's own machine, where
# the desk's public https endpoint reaches it the same way).
if [ -n "$CFG" ]; then
    sed -i 's|endpoint = "https://|endpoint = "http://|' "$CFG"
    "$V" account --config "$CFG" > "$LAB/account.log" 2>&1; RC=$?
    [ "$RC" = 0 ]; check $? "vallum account read the desk (rc=$RC)"
    grep -q 'laptop\|u0001' "$LAB/account.log"; check $? "the account report names the enrolled device"
    grep -qi 'trial' "$LAB/account.log"; check $? "the account report carries the plan"
fi

note "vallum://account — the account handoff records locally (ns2, headless)"
ns_client vallum-uri "vallum://account?token=$TOKEN&desk=https%3A%2F%2F127.0.0.1%3A8400" \
    > "$LAB/uri-account.log" 2>&1; RC=$?
[ "$RC" = 0 ]; check $? "vallum://account recorded (rc=$RC)"
ACCT="$LAB/home/.config/vallum/account.toml"
[ -f "$ACCT" ]; check $? "account.toml exists"
if [ -f "$ACCT" ]; then
    MODE=$(stat -c %a "$ACCT")
    [ "$MODE" = 600 ]; check $? "account.toml is 0600 (got $MODE)"
    sed -i 's|endpoint = "https://|endpoint = "http://|' "$ACCT"
    "$V" account --config "$ACCT" > "$LAB/account2.log" 2>&1; RC=$?
    [ "$RC" = 0 ]; check $? "vallum account reads the handoff config (rc=$RC)"
    grep -qi 'trial' "$LAB/account2.log"; check $? "the handoff account answers with the plan"
fi

note "NEGATIVE: the handler refuses what it must"
ns_client vallum-uri "vallum://exec?ticket=x&account=$TOKEN" > "$LAB/refuse.log" 2>&1; RC=$?
[ "$RC" -ne 0 ]; check $? "an unknown action is refused (rc=$RC)"
ns_client vallum-uri "vallum://join?ticket=notaticket&account=$TOKEN" > "$LAB/refuse2.log" 2>&1; RC=$?
[ "$RC" -ne 0 ]; check $? "a garbage ticket is refused (rc=$RC)"

note "NEGATIVE: a different account never clobbers account.toml"
OTHER=$(python3 -c 'print("f"*32)')
ns_client vallum-uri "vallum://account?token=$OTHER" > "$LAB/clobber.log" 2>&1; RC=$?
[ "$RC" -ne 0 ]; check $? "a different account number is refused (rc=$RC)"
grep -q "different account" "$LAB/clobber.log"; check $? "the refusal names the remedy"
grep -q "$TOKEN" "$ACCT" 2>/dev/null; check $? "the recorded account is untouched"
ns_client vallum-uri "vallum://account?token=$TOKEN" > "$LAB/idem.log" 2>&1; RC=$?
[ "$RC" = 0 ]; check $? "the same account re-records idempotently (rc=$RC)"

note "connect-link lab FAIL=$FAIL"
exit $FAIL
INNER

say "running the lab in an unprivileged user namespace (no docker, no VPS)"
# -m (mount namespace) is required: the lab hides host /etc/vallum and /run
# behind tmpfs, and a tmpfs mount needs a mount ns owned by the user ns.
LAB_OUT=$(unshare -Urnm bash "$WORK/inner.sh" "$REPO/target/release/vallum" "$WORK" "$REPO" 2>&1)
LAB_RC=$?
if [ "$LAB_RC" -ne 0 ]; then
    say "unprivileged namespaces unavailable - trying sudo -n (AppArmor fallback)"
    LAB_OUT2=$(sudo -n unshare -Urnm bash "$WORK/inner.sh" "$REPO/target/release/vallum" "$WORK" "$REPO" 2>&1)
    LAB_RC=$?
    if [ "$LAB_RC" -eq 0 ]; then LAB_OUT=$LAB_OUT2; else LAB_OUT="$LAB_OUT
$LAB_OUT2"; fi
fi
printf '%s\n' "$LAB_OUT"
ASSERTIONS=$(printf '%s\n' "$LAB_OUT" | grep -c '^   ok')
if [ "$LAB_RC" -ne 0 ]; then
    echo "== FAIL - the connect-link lab did not pass (see the FAIL line above)"
    exit 1
fi
echo "== PASS - a colleague's click path: signup, Connect link, vallum-uri, tunnel, account"
