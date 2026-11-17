#!/usr/bin/env python3
"""Tests for the Vallum enrolment desk.

The desk's whole value is that its accounting is *right*: a quota that never
matches is a quota that never fires, and a passing expiry test makes that
look alive. So the tests are mostly about the accounting, and they run
against a fake daemon — the `Daemon` port is what makes that possible.

    python3 -m unittest discover -s service -p 'test_*.py'
"""

import dataclasses
import datetime
import importlib.util
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from importlib.machinery import SourceFileLoader

DESK_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vallum-desk")
_spec = importlib.util.spec_from_loader("vallum_desk", SourceFileLoader("vallum_desk", DESK_PATH))
assert _spec is not None and _spec.loader is not None, "the desk module must load"
desk_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(desk_module)

Desk = desk_module.Desk
DeskConfig = desk_module.DeskConfig
connection_state = desk_module.connection_state
SESSION_LIVE_SECONDS = desk_module.SESSION_LIVE_SECONDS


class FakeDaemon(desk_module.Daemon):
    """A daemon that is a dictionary with a method or two."""

    def __init__(self, counters=None, refuse=False, refuse_remove=False, liveness=None,
                 refuse_liveness=False):
        self._counters = counters or {}
        self._refuse = refuse
        self._refuse_remove = refuse_remove
        self._liveness = liveness or {}
        self._refuse_liveness = refuse_liveness
        self.removed = []
        self.minted = []

    def mint_ticket(self, peer):
        if self._refuse:
            raise RuntimeError("the daemon said no")
        self.minted.append(peer)
        return f"vallum1-join:203.0.113.9:51922/{peer}/deadbeef/token/fingerprint"

    def counters(self):
        return dict(self._counters)

    def liveness(self):
        if self._refuse_liveness:
            raise RuntimeError("the daemon did not answer")
        return dict(self._liveness)

    def remove(self, peer):
        if self._refuse_remove:
            raise RuntimeError("the daemon said no")
        if peer in getattr(self, "missing_peers", ()):
            raise RuntimeError(f"vallum: no peer named `{peer}`")
        self.removed.append(peer)


class DeskTestCase(unittest.TestCase):
    """A desk over a temporary database, with a fake daemon."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.codes_path = os.path.join(self.tempdir.name, "codes.txt")
        with open(self.codes_path, "w") as f:
            f.write("friend-code-1\nfriend-code-2\n")
        self.config = DeskConfig(
            state=os.path.join(self.tempdir.name, "desk.sqlite"),
            codes=self.codes_path,
            admin_token="admin-secret",
            trial_days=14,
            trial_bytes=1000,
            sweep_secs=300,
            config="/etc/vallum/server.toml",
            bind="127.0.0.1",
            port=0,
        )
        self.daemon = FakeDaemon()
        self.desk = Desk(self.config, self.daemon)

    def signup(self, code="friend-code-1", name="friend"):
        return self.desk.signup({"code": code, "name": name})


class StateFileModeTests(DeskTestCase):
    """The account database holds the only credential the desk issues."""

    def test_database_is_not_world_readable(self):
        # sqlite3 creates the file 0644 under the default umask, and every
        # account token would then be readable by any local account — the CI
        # runner user on the same host included. `open_database` tightens it.
        mode = os.stat(self.config.state).st_mode & 0o777
        self.assertEqual(mode, 0o600, f"{self.config.state} is mode {mode:o}, not 600")


class SignupTests(DeskTestCase):

    def test_a_valid_code_returns_a_ticket_and_creates_an_account(self):
        code, payload = self.signup()
        self.assertEqual(code, 200)
        self.assertTrue(payload["ticket"].startswith("vallum1-join:"))
        self.assertEqual(payload["peer"], "u0001-friend")
        row = self.desk.db.execute("SELECT * FROM accounts").fetchone()
        self.assertEqual(row["peer"], "u0001-friend")
        self.assertEqual(row["status"], "active")

    def test_an_unknown_code_is_refused(self):
        code, payload = self.signup(code="not-a-code")
        self.assertEqual(code, 403)
        self.assertIn("invite-only", payload["error"])
        self.assertEqual(self.daemon.minted, [])

    def test_a_code_is_single_use(self):
        self.assertEqual(self.signup()[0], 200)
        code, payload = self.signup(name="second")
        self.assertEqual(code, 403)
        self.assertIn("already used", payload["error"])

    def test_a_daemon_refusal_is_reported_not_swallowed(self):
        self.daemon._refuse = True
        code, payload = self.signup()
        self.assertEqual(code, 502)
        self.assertIn("refused the enrolment", payload["error"])

    def test_peer_names_differ_in_their_first_eight_characters(self):
        # The kernel's interface-name ceiling truncates at fifteen characters,
        # so two peers sharing a prefix would collide on one machine.
        self.assertEqual(self.signup(name="alpha")[1]["peer"], "u0001-alpha")
        self.assertEqual(self.signup(code="friend-code-2", name="beta")[1]["peer"], "u0002-beta")


class DaemonCliTests(unittest.TestCase):
    """The CLI port: what the desk reads from the daemon's own output."""

    def test_the_ticket_is_read_from_the_json_field(self):
        # `peer invite --json` is the machine interface. A regex over the
        # human report is the class of bug that once matched a usage string.
        with tempfile.TemporaryDirectory() as tempdir:
            cli = os.path.join(tempdir, "vallum")
            with open(cli, "w") as f:
                f.write("#!/bin/sh\nprintf '%s\\n' "
                        "'{\"ticket\":\"vallum1-join:203.0.113.9:51922/laptop/id/token/fp\"}'\n")
            os.chmod(cli, 0o755)
            daemon = desk_module.DaemonCli("/etc/vallum/server.toml", cli=cli)
            self.assertEqual(
                daemon.mint_ticket("laptop"),
                "vallum1-join:203.0.113.9:51922/laptop/id/token/fp",
            )

    def _daemon_emitting(self, body):
        """A DaemonCli whose `vallum show --json` prints `body`."""
        tempdir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tempdir, ignore_errors=True))
        cli = os.path.join(tempdir, "vallum")
        with open(cli, "w") as f:
            f.write("#!/bin/sh\ncat <<'JSON'\n" + body + "\nJSON\n")
        os.chmod(cli, 0o755)
        return desk_module.DaemonCli("/etc/vallum/server.toml", cli=cli)

    def test_liveness_is_read_from_the_daemons_own_handshake_field(self):
        # `last_handshake` is the same field the daemon renders
        # vallum_peer_handshake_age_seconds from, so the number the page shows
        # and the number a scraper sees cannot disagree.
        daemon = self._daemon_emitting(json.dumps({"peers": [
            {"name": "laptop", "last_handshake": {"sec": 1794934000, "nsec": 1},
             "tx_bytes": 1, "rx_bytes": 2},
        ]}))
        self.assertEqual(daemon.liveness(), {"laptop": 1794934000})

    def test_a_peer_that_never_handshaked_reads_as_None_not_zero(self):
        # Zero is a real unix time (1970). Returning it would date every unused
        # device to the epoch and, worse, read as `offline` rather than `never`.
        daemon = self._daemon_emitting(json.dumps({"peers": [
            {"name": "laptop", "last_handshake": None, "tx_bytes": 0, "rx_bytes": 0},
        ]}))
        self.assertEqual(daemon.liveness(), {"laptop": None})

    def test_a_snapshot_without_a_peers_list_fails_loudly(self):
        # The alternative — an empty dict — makes every device render `unknown`
        # and hides a shape change in the daemon's JSON behind a calm page.
        daemon = self._daemon_emitting(json.dumps({"interfaces": []}))
        with self.assertRaises(RuntimeError):
            daemon.liveness()

    def test_the_base_port_says_it_cannot_answer_rather_than_raising(self):
        # `None` is "could not ask". An empty dict is a different fact — the
        # daemon answered and has no peers — and conflating the two is how a page
        # tells a user "never connected" about a device the server never had.
        self.assertIsNone(desk_module.Daemon().liveness())


class StatusTests(DeskTestCase):

    def test_status_reports_the_bytes_used_for_the_account_peer(self):
        _, signup_payload = self.signup()
        peer = signup_payload["peer"]
        # The daemon keys its counters by peer NAME. A reader that looked them
        # up by fingerprint would report zero here — which is how a quota
        # stops firing while the expiry path keeps working.
        self.daemon._counters = {peer: 23838}
        code, payload = self.desk.status(signup_payload["token"])
        self.assertEqual(code, 200)
        self.assertEqual(payload["bytes_used"], 23838)

    def test_an_unknown_token_is_not_found(self):
        code, payload = self.desk.status("nope")
        self.assertEqual(code, 404)


class EnforcementTests(DeskTestCase):

    def account_row(self, peer):
        return self.desk.db.execute("SELECT * FROM accounts WHERE peer=?", (peer,)).fetchone()

    def test_an_expired_account_loses_its_peer(self):
        _, signup_payload = self.signup()
        peer = signup_payload["peer"]
        self.desk.db.execute("UPDATE accounts SET expires='2020-01-01' WHERE peer=?", (peer,))
        actions = self.desk.sweep_once()
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["reason"], "expired")
        self.assertEqual(self.daemon.removed, [peer])
        self.assertEqual(self.account_row(peer)["status"], "expired")

    def test_an_account_over_its_byte_cap_loses_its_peer(self):
        _, signup_payload = self.signup()
        peer = signup_payload["peer"]
        self.daemon._counters = {peer: 5000}  # cap is 1000
        actions = self.desk.sweep_once()
        self.assertEqual(actions[0]["reason"], "overquota")
        self.assertEqual(self.daemon.removed, [peer])

    def test_a_healthy_account_is_left_alone(self):
        _, signup_payload = self.signup()
        peer = signup_payload["peer"]
        self.daemon._counters = {peer: 10}
        self.assertEqual(self.desk.sweep_once(), [])
        self.assertEqual(self.daemon.removed, [])

    def test_an_account_expiring_today_is_expired(self):
        # Inclusive: "expires 2026-11-16" means it is already spent on the
        # 16th, not at the end of it.
        _, signup_payload = self.signup()
        peer = signup_payload["peer"]
        today = desk_module.datetime.date.today().isoformat()
        self.desk.db.execute("UPDATE accounts SET expires=? WHERE peer=?", (today, peer))
        self.assertEqual(self.desk.sweep_once()[0]["reason"], "expired")

    def test_a_failed_removal_is_retried_instead_of_marked_revoked(self):
        # The row is what the next sweep reads, so marking it before the peer
        # is actually gone hides a live peer from every future pass.
        _, signup_payload = self.signup()
        peer = signup_payload["peer"]
        self.desk.db.execute("UPDATE accounts SET expires='2020-01-01' WHERE peer=?", (peer,))
        self.daemon._refuse_remove = True
        action = self.desk.sweep_once()[0]
        self.assertIn("error", action)
        self.assertEqual(self.account_row(peer)["status"], "active")
        self.daemon._refuse_remove = False
        self.assertEqual(self.desk.sweep_once()[0]["reason"], "expired")
        self.assertEqual(self.account_row(peer)["status"], "expired")
        self.assertEqual(self.daemon.removed, [peer])

    def test_a_peer_that_was_never_created_marks_the_account_without_retrying(self):
        # A ticket minted but never redeemed leaves no peer to remove: "no
        # peer named" is the goal state already holding, not a failure, and a
        # row that retries it forever would never finish sweeping.
        _, signup_payload = self.signup()
        peer = signup_payload["peer"]
        self.desk.db.execute("UPDATE accounts SET expires='2020-01-01' WHERE peer=?", (peer,))
        self.daemon.missing_peers = {peer}
        action = self.desk.sweep_once()[0]
        self.assertNotIn("error", action)
        self.assertEqual(action["reason"], "expired")
        self.assertEqual(self.account_row(peer)["status"], "expired")


class OnDemandTests(DeskTestCase):
    """Open signup: no invite code, bounded per IP and by capacity."""

    def open_desk(self):
        self.config.open_signup = True
        self.config.open_trial_bytes = 500
        self.config.max_active_accounts = 2
        self.config.signup_ip_day_limit = 2

    def test_open_mode_signs_up_without_a_code(self):
        self.open_desk()
        code, payload = self.desk.signup({"name": "walk-in"}, client_ip="198.51.100.9")
        self.assertEqual(code, 200)
        self.assertEqual(payload["bytes_cap"], 500)  # the smaller anonymous trial

    def test_open_mode_still_honours_invite_codes_at_the_full_cap(self):
        self.open_desk()
        code, payload = self.signup()  # friend-code-1, cap is trial_bytes=1000
        self.assertEqual(code, 200)
        self.assertEqual(payload["bytes_cap"], 1000)

    def test_anonymous_signups_are_limited_per_ip_per_day(self):
        self.open_desk()
        self.config.max_active_accounts = 10  # capacity is a separate test
        first = self.desk.signup({"name": "a"}, client_ip="198.51.100.9")
        second = self.desk.signup({"name": "b"}, client_ip="198.51.100.9")
        third = self.desk.signup({"name": "c"}, client_ip="198.51.100.9")
        self.assertEqual(first[0], 200)
        self.assertEqual(second[0], 200)
        self.assertEqual(third[0], 429)
        # a different address is not affected by this one's history
        other = self.desk.signup({"name": "d"}, client_ip="198.51.100.10")
        self.assertEqual(other[0], 200)

    def test_capacity_is_a_ceiling_not_a_formality(self):
        self.open_desk()
        for n in range(2):
            self.assertEqual(
                self.desk.signup({"name": f"filler{n}"}, client_ip=f"198.51.100.{n}")[0], 200)
        code, payload = self.desk.signup({"name": "one-too-many"}, client_ip="198.51.100.9")
        self.assertEqual(code, 503)
        self.assertIn("capacity", payload["error"])

    def test_closed_mode_still_refuses_without_a_code(self):
        code, payload = self.desk.signup({"name": "walk-in"}, client_ip="198.51.100.9")
        self.assertEqual(code, 403)


class HttpTests(DeskTestCase):
    """The wire, not just the logic: a bad body is answered, never dropped."""

    def setUp(self):
        super().setUp()
        self.config.open_signup = True
        self.server = desk_module.ThreadingHTTPServer(("127.0.0.1", 0), desk_module.make_handler(self.desk))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def post(self, path, body, content_type, headers=None):
        all_headers = {"Content-Type": content_type}
        all_headers.update(headers or {})
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=body.encode(),
            headers=all_headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode()

    def test_the_page_header_renders_the_operator_name(self):
        self.desk.config.operator_name = "wingman tunnel"
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=5) as r:
            page = r.read().decode()
        self.assertIn("<h1>wingman tunnel</h1>", page)

    def test_the_index_needs_no_script(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=5) as r:
            page = r.read().decode()
        self.assertEqual(r.status, 200)
        self.assertNotIn("<script", page)
        self.assertNotIn('name="code"', page)  # open mode: no invite field

    def test_the_form_path_answers_with_a_ticket_page(self):
        status, page = self.post("/signup", "name=form-user", "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertIn("Your join ticket", page)
        self.assertIn("vallum1-join:", page)

    def test_a_json_body_sent_as_a_form_is_named_as_the_mistake(self):
        # curl -d sends form-encoding by default; the desk must say so rather
        # than report "bad admin token" for a body it never parsed.
        status, page = self.post("/api/admin/sweep", '{"admin_token":"x"}',
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 500)
        self.assertIn("application/json", page)

    def test_the_json_api_still_works(self):
        status, body = self.post("/api/signup", '{"name":"json-user"}', "application/json")
        self.assertEqual(status, 200)
        self.assertIn("vallum1-join:", body)

    def test_the_per_ip_limit_sees_the_visitor_behind_the_proxy(self):
        # The desk is loopback-only and fronted by Caddy. Reading
        # client_address would make every visitor 127.0.0.1 and turn the
        # per-IP limit into a global three-signups-a-day limit.
        self.config.signup_ip_day_limit = 1
        same = {"X-Forwarded-For": "198.51.100.9"}
        self.assertEqual(
            self.post("/api/signup", '{"name":"one"}', "application/json", same)[0], 200)
        self.assertEqual(
            self.post("/api/signup", '{"name":"two"}', "application/json", same)[0], 429)
        other = {"X-Forwarded-For": "198.51.100.10"}
        self.assertEqual(
            self.post("/api/signup", '{"name":"three"}', "application/json", other)[0], 200)


class LivenessTests(DeskTestCase):
    """/api/account answers "is this device working?" as well as "was it
    issued?". `status` is a provisioning fact; a device that never handshaked
    used to render as plain `active`, which is a lie about the only thing the
    user is looking for."""

    def _token(self):
        _, payload = self.signup()
        return payload["token"]

    def _account(self, liveness_mapping):
        self.desk.daemon = FakeDaemon(liveness=liveness_mapping)
        return self.desk.account(self._token())

    def test_a_device_that_never_handshaked_is_never_not_active(self):
        # The peer exists on the server and has not connected: `never`.
        code, view = self._account({"u0001-friend": None})
        self.assertEqual(code, 200)
        device = view["devices"][0]
        self.assertEqual(device["status"], "active")
        self.assertEqual(device["connection"], "never")
        self.assertIsNone(device["last_seen_seconds"])

    def test_a_recent_handshake_is_live_with_its_age(self):
        now = int(time.time())
        code, view = self._account({"u0001-friend": now - 42})
        self.assertEqual(code, 200)
        device = view["devices"][0]
        self.assertEqual(device["connection"], "live")
        self.assertIn(device["last_seen_seconds"], (42, 43))

    def test_a_handshake_older_than_the_reject_window_is_offline(self):
        now = int(time.time())
        _, view = self._account({"u0001-friend": now - 4000})
        device = view["devices"][0]
        self.assertEqual(device["connection"], "offline")
        self.assertGreater(device["last_seen_seconds"], SESSION_LIVE_SECONDS)

    def test_the_boundary_is_the_protocols_reject_window(self):
        # 180 s is where the daemon stops accepting the session. Off by one here
        # means the page calls a dead tunnel live, so pin both sides.
        now = 1_000_000
        self.assertEqual(connection_state(now - SESSION_LIVE_SECONDS, now)[0], "live")
        self.assertEqual(connection_state(now - SESSION_LIVE_SECONDS - 1, now)[0], "offline")

    def test_a_device_the_server_has_no_peer_for_is_missing_not_never(self):
        # Found on the live server after the first deploy: all 14 desk devices
        # had no peer on the daemon (the peer table had been rebuilt when the
        # server was renumbered), and the page said "never connected" — which
        # reads as "try connecting". It cannot connect; there is nothing to
        # connect to. The fix is a new ticket.
        code, view = self._account({})
        self.assertEqual(code, 200)
        device = view["devices"][0]
        self.assertEqual(device["status"], "active")
        self.assertEqual(device["connection"], "missing")
        self.assertIsNone(device["last_seen_seconds"])

    def test_a_daemon_that_cannot_answer_says_unknown_and_keeps_the_page(self):
        # Not `offline`: telling a user their tunnel is down because the
        # operator's daemon was busy is a false alarm in the one place they go
        # to check. Not a 500 either — the quota and revoke still work.
        self.desk.daemon = FakeDaemon(refuse_liveness=True)
        code, view = self.desk.account(self._token())
        self.assertEqual(code, 200)
        self.assertEqual(view["devices"][0]["connection"], "unknown")
        self.assertEqual(view["devices"][0]["status"], "active")

    def test_a_revoked_device_is_not_described_as_a_connection(self):
        # The daemon has no peer record for it. "never connected" would be a
        # claim about a device that no longer exists on the server.
        token = self._token()
        self.desk.daemon = FakeDaemon(liveness={"u0001-friend": int(time.time()) - 5})
        code, view = self.desk.account(token)
        self.assertEqual(code, 200)
        self.assertEqual(view["devices"][0]["connection"], "live")
        self.desk.db.execute("UPDATE peers SET status='removed' WHERE peer='u0001-friend'")
        code, view = self.desk.account(token)
        self.assertEqual(code, 200)
        self.assertEqual(view["devices"][0]["status"], "removed")
        self.assertIsNone(view["devices"][0]["connection"])

    def test_a_future_handshake_does_not_produce_a_negative_age(self):
        # Clock skew between the daemon and the desk is not a user-facing
        # duration; `-3s ago` is a bug report waiting to happen.
        now = int(time.time())
        _, view = self._account({"u0001-friend": now + 300})
        self.assertEqual(view["devices"][0]["last_seen_seconds"], 0)


class AccountPageTests(HttpTests):
    """The account surface: the bearer token travels POST bodies only —
    never the request line — and every rendered page is private."""

    def _token(self):
        status, body = self.post("/api/signup", '{"name":"friend"}', "application/json")
        self.assertEqual(status, 200)
        return json.loads(body)["token"]

    def post_headers(self, path, body, content_type):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=body.encode(),
            headers={"Content-Type": content_type}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, dict(response.headers), response.read().decode()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers), error.read().decode()

    def get(self, path):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, dict(response.headers), response.read().decode()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers), error.read().decode()

    def test_the_account_endpoint_returns_the_full_view(self):
        token = self._token()
        self.desk.add_device({"token": token, "name": "laptop"})
        status, body = self.post("/api/account", json.dumps({"token": token}),
                                 "application/json")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["plan"], "trial")
        self.assertEqual(payload["bytes_cap"], 5 * 1024 ** 3)
        self.assertEqual([d["peer"] for d in payload["devices"]],
                         ["u0001-friend", "u0002-laptop"])
        self.assertEqual(payload["devices"][0]["status"], "active")

    def test_the_token_is_not_accepted_in_the_url(self):
        token = self._token()
        status, _, body = self.get(f"/api/status?token={token}")
        self.assertEqual(status, 410)
        self.assertNotIn("u0001-friend", body)

    def test_status_by_post_still_works(self):
        token = self._token()
        status, body = self.post("/api/status", json.dumps({"token": token}),
                                 "application/json")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["peer"], "u0001-friend")

    def test_the_account_page_is_private_and_noindexed(self):
        token = self._token()
        status, headers, page = self.post_headers(
            "/account", f"token={token}", "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(headers.get("X-Robots-Tag"), "noindex")
        self.assertIn("u0001-friend", page)

    def test_the_account_shell_needs_no_script(self):
        status, _, page = self.get("/account")
        self.assertEqual(status, 200)
        self.assertNotIn("<script", page)
        self.assertIn('name="token"', page)

    def test_the_account_page_escapes_the_label(self):
        token = self._token()
        self.desk.db.execute(
            "UPDATE accounts SET label='<img onerror=x>' WHERE token=?", (token,))
        _, _, page = self.post_headers(
            "/account", f"token={token}", "application/x-www-form-urlencoded")
        self.assertNotIn("<img", page)
        self.assertIn("&lt;img", page)

    def test_the_page_revokes_only_the_accounts_own_device(self):
        token = self._token()
        self.desk.add_device({"token": token, "name": "laptop"})
        status, _, _ = self.post_headers(
            "/account/revoke", f"token={token}&peer=u0002-laptop",
            "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertEqual(self.daemon.removed, ["u0002-laptop"])
        # Another account's peer is not ours to remove.
        other = self.desk.signup({"name": "other"})
        other_peer = other[1]["peer"]
        status, _, _ = self.post_headers(
            "/account/revoke", f"token={token}&peer={other_peer}",
            "application/x-www-form-urlencoded")
        self.assertEqual(status, 404)
        self.assertNotIn(other_peer, self.daemon.removed)

    def test_the_ticket_page_emits_the_deep_link_and_the_number(self):
        status, page = self.post("/signup", "name=form-user",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        payload = self.desk.db.execute("SELECT token FROM accounts").fetchone()
        token = payload["token"]
        from urllib.parse import quote
        expected = (f"vallum://join?ticket={quote('vallum1-join:203.0.113.9:51922/u0001-form-use/deadbeef/token/fingerprint', safe='')}"
                    f"&account={token}")
        self.assertIn(expected, page)
        # The URI is fired by script — the token must never sit in an href
        # or another attribute a prefetcher or Referer header would carry.
        import re
        for href in re.findall(r'href="([^"]*)"', page):
            self.assertNotIn(token, href)

    def test_the_ticket_page_names_the_account_number(self):
        status, page = self.post("/signup", "name=form-user",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        token = self.desk.db.execute("SELECT token FROM accounts").fetchone()["token"]
        self.assertIn("account number", page)
        self.assertIn(token, page)

    def test_the_signup_json_carries_the_deep_link(self):
        status, body = self.post("/api/signup", '{"name":"json-user"}',
                                 "application/json")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["connect"].startswith("vallum://join?ticket="))
        self.assertIn(f"&account={payload['token']}", payload["connect"])

    def test_the_add_device_form_mints_a_bound_ticket(self):
        token = self._token()
        status, _, page = self.post_headers(
            "/account/device", f"token={token}&name=laptop",
            "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertIn("vallum1-join:", page)

    def test_the_voucher_box_applies_the_code(self):
        token = self._token()
        _, minted = self.desk._mint_code({"bytes": 5000})
        status, _, _ = self.post_headers(
            "/account/voucher", f"token={token}&code={minted['code']}",
            "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        row = self.desk.db.execute("SELECT bytes_cap FROM accounts").fetchone()
        self.assertEqual(row["bytes_cap"], 5 * 1024 ** 3 + 5000)


class MigrationTests(DeskTestCase):
    """The schema's forward path: a pre-version database becomes v1."""

    def legacy_db(self):
        """A database the way the alpha desk wrote it: accounts with an
        inline `peer` column, codes with no payload, no peers table, and no
        `user_version` to say so."""
        path = os.path.join(self.tempdir.name, "legacy.sqlite")
        conn = sqlite3.connect(path)
        conn.executescript("""
            CREATE TABLE accounts (
                id INTEGER PRIMARY KEY, peer TEXT UNIQUE NOT NULL,
                label TEXT NOT NULL, token TEXT UNIQUE NOT NULL,
                code TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'trial',
                created TEXT NOT NULL, expires TEXT NOT NULL,
                bytes_cap INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'active', paid_until TEXT);
            CREATE TABLE codes (code TEXT PRIMARY KEY,
                created TEXT NOT NULL, used_by TEXT);
            INSERT INTO accounts (peer,label,token,code,created,expires,bytes_cap,status)
                VALUES ('u0001-old','old-friend','tok-1','legacy','2026-11-01',
                        '2027-01-01',1000,'active'),
                       ('u0002-old','older','tok-2','legacy','2026-11-02',
                        '2027-01-01',1000,'expired');
        """)
        conn.close()
        return path

    def test_a_pre_version_database_migrates_forward(self):
        config = dataclasses.replace(self.config, state=self.legacy_db())
        desk = Desk(config, self.daemon)
        self.addCleanup(desk.db.close)
        version = desk.db.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(version, 1)
        rows = desk.db.execute("SELECT peer, status FROM peers ORDER BY peer").fetchall()
        self.assertEqual([r["peer"] for r in rows], ["u0001-old", "u0002-old"])
        # The legacy column stays populated — the expand step keeps old
        # readers working while the contract is still ahead of us.
        accounts = desk.db.execute("SELECT peer FROM accounts ORDER BY peer").fetchall()
        self.assertEqual([a["peer"] for a in accounts], ["u0001-old", "u0002-old"])
        columns = {r[1] for r in desk.db.execute("PRAGMA table_info(codes)")}
        self.assertTrue({"days", "bytes", "plan"} <= columns)

    def test_a_database_newer_than_this_build_is_refused(self):
        path = os.path.join(self.tempdir.name, "newer.sqlite")
        conn = sqlite3.connect(path)
        conn.executescript(desk_module.SCHEMA)
        conn.execute("PRAGMA user_version=99")
        conn.close()
        config = dataclasses.replace(self.config, state=path)
        with self.assertRaises(RuntimeError):
            Desk(config, self.daemon)


class PeersRelationTests(DeskTestCase):
    """Every reader consults the peers relation, not the legacy column."""

    def test_signup_writes_the_peer_row_and_keeps_the_legacy_column(self):
        _, payload = self.signup()
        account = self.desk.db.execute("SELECT * FROM accounts").fetchone()
        peer = self.desk.db.execute(
            "SELECT * FROM peers WHERE account_id=?", (account["id"],)).fetchone()
        self.assertIsNotNone(peer)
        self.assertEqual(peer["peer"], payload["peer"])
        self.assertEqual(peer["status"], "active")
        self.assertEqual(account["peer"], payload["peer"])

    def test_the_relation_falls_back_to_the_legacy_column(self):
        _, payload = self.signup()
        self.desk.db.execute("DELETE FROM peers")
        code, status = self.desk.status(payload["token"])
        self.assertEqual(code, 200)
        self.assertEqual(status["peer"], payload["peer"])

    def test_adopting_writes_the_peers_row(self):
        self.desk.admin("/api/admin/adopt",
                        {"admin_token": "admin-secret", "peer": "existing-peer"})
        row = self.desk.db.execute(
            "SELECT * FROM peers WHERE peer='existing-peer'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "active")

    def test_revoking_marks_the_peers_row_removed(self):
        _, payload = self.signup()
        peer = payload["peer"]
        self.desk.db.execute(
            "UPDATE accounts SET expires='2020-01-01' WHERE peer=?", (peer,))
        self.desk.sweep_once()
        row = self.desk.db.execute("SELECT status FROM peers WHERE peer=?", (peer,)).fetchone()
        self.assertEqual(row["status"], "removed")


class CodePlanTests(DeskTestCase):
    """A minted code carries a plan — days, a byte cap, a label — and a
    signup that presents the code lands the payload instead of the trial."""

    def test_minting_a_code_with_a_payload_stores_it(self):
        status, minted = self.desk._mint_code({"days": 30, "bytes": 5000, "plan": "plus"})
        self.assertEqual(status, 200)
        row = self.desk.db.execute(
            "SELECT days, bytes, plan FROM codes WHERE code=?", (minted["code"],)).fetchone()
        self.assertEqual((row["days"], row["bytes"], row["plan"]), (30, 5000, "plus"))

    def test_a_payload_code_signup_lands_the_codes_plan(self):
        _, minted = self.desk._mint_code({"days": 30, "bytes": 5000, "plan": "plus"})
        status, payload = self.signup(code=minted["code"], name="member")
        self.assertEqual(status, 200)
        row = self.desk.db.execute(
            "SELECT * FROM accounts WHERE peer=?", (payload["peer"],)).fetchone()
        self.assertEqual(row["plan"], "plus")
        self.assertEqual(row["bytes_cap"], 5000)
        expected = (datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(days=30)).date().isoformat()
        self.assertEqual(row["expires"], expected)

    def test_a_payload_less_code_still_lands_the_trial(self):
        _, minted = self.desk._mint_code({})
        status, payload = self.signup(code=minted["code"], name="trial-friend")
        self.assertEqual(status, 200)
        row = self.desk.db.execute(
            "SELECT * FROM accounts WHERE peer=?", (payload["peer"],)).fetchone()
        self.assertEqual(row["plan"], "trial")
        self.assertEqual(row["bytes_cap"], 1000)

    def test_a_code_redeems_once_even_under_a_race(self):
        _, minted = self.desk._mint_code({})
        results = []
        threads = [threading.Thread(
            target=lambda n: results.append(
                self.desk.signup({"code": minted["code"], "name": n})[0]),
            args=(f"racer-{i}",)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results), [200, 403])
        self.assertEqual(
            self.desk.db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0], 1)


class DevicesTests(DeskTestCase):
    """One account token carries several devices: a ticket minted through
    /api/devices binds the account's plan, the cap is enforced under race,
    and revocation splits into per-device and per-account."""

    def _token(self):
        _, payload = self.signup()
        return payload["token"]

    def test_an_account_adds_a_device_and_gets_a_ticket(self):
        token = self._token()
        code, payload = self.desk.add_device({"token": token, "name": "laptop"})
        self.assertEqual(code, 200)
        self.assertTrue(payload["ticket"].startswith("vallum1-join:"))
        self.assertEqual(payload["peer"], "u0002-laptop")
        rows = self.desk.db.execute(
            "SELECT peer FROM peers WHERE status='active' ORDER BY peer").fetchall()
        self.assertEqual([r["peer"] for r in rows], ["u0001-friend", "u0002-laptop"])

    def test_the_device_ticket_binds_the_accounts_plan(self):
        _, minted = self.desk._mint_code({"days": 30, "bytes": 5000, "plan": "plus"})
        _, signup_payload = self.signup(code=minted["code"], name="member")
        code, payload = self.desk.add_device(
            {"token": signup_payload["token"], "name": "laptop"})
        self.assertEqual(code, 200)
        self.assertEqual(payload["plan"], "plus")
        self.assertEqual(payload["bytes_cap"], 5000)

    def test_a_device_against_an_unknown_token_is_refused(self):
        code, payload = self.desk.add_device({"token": "nope", "name": "laptop"})
        self.assertEqual(code, 404)
        self.assertEqual(self.daemon.minted, [])

    def test_a_device_against_a_revoked_account_is_refused(self):
        token = self._token()
        peer = self.daemon.minted[0]
        self.desk.admin("/api/admin/revoke-account",
                        {"admin_token": "admin-secret", "peer": peer})
        code, payload = self.desk.add_device({"token": token, "name": "laptop"})
        self.assertEqual(code, 403)

    def test_the_device_cap_is_a_ceiling(self):
        self.desk.config.device_cap = 2
        token = self._token()
        code, _ = self.desk.add_device({"token": token, "name": "laptop"})
        self.assertEqual(code, 200)
        code, payload = self.desk.add_device({"token": token, "name": "phone"})
        self.assertEqual(code, 429)
        self.assertIn("device limit", payload["error"])
        self.assertEqual(
            self.desk.db.execute("SELECT COUNT(*) FROM peers").fetchone()[0], 2)

    def test_the_cap_holds_under_a_race(self):
        self.desk.config.device_cap = 2
        token = self._token()
        results = []
        threads = [threading.Thread(
            target=lambda n: results.append(
                self.desk.add_device({"token": token, "name": n})[0]),
            args=(f"dev-{i}",)) for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results), [200, 429])
        self.assertEqual(
            self.desk.db.execute(
                "SELECT COUNT(*) FROM peers WHERE status='active'").fetchone()[0], 2)

    def test_devices_share_the_account_byte_pool(self):
        token = self._token()
        self.desk.add_device({"token": token, "name": "laptop"})
        self.daemon._counters = {"u0001-friend": 600, "u0002-laptop": 600}
        actions = self.desk.sweep_once()
        self.assertEqual(actions[0]["reason"], "overquota")
        self.assertEqual(sorted(self.daemon.removed), ["u0001-friend", "u0002-laptop"])
        row = self.desk.db.execute("SELECT status FROM accounts").fetchone()
        self.assertEqual(row["status"], "overquota")

    def test_per_device_revoke_keeps_the_account(self):
        token = self._token()
        _, device = self.desk.add_device({"token": token, "name": "laptop"})
        code, _ = self.desk.admin("/api/admin/revoke",
                                  {"admin_token": "admin-secret", "peer": device["peer"]})
        self.assertEqual(code, 200)
        self.assertEqual(self.daemon.removed, ["u0002-laptop"])
        row = self.desk.db.execute("SELECT status FROM accounts").fetchone()
        self.assertEqual(row["status"], "active")
        _, status = self.desk.status(token)
        self.assertEqual(status["peers"], ["u0001-friend"])

    def test_account_revoke_removes_every_device(self):
        token = self._token()
        self.desk.add_device({"token": token, "name": "laptop"})
        code, _ = self.desk.admin("/api/admin/revoke-account",
                                  {"admin_token": "admin-secret", "peer": "u0001-friend"})
        self.assertEqual(code, 200)
        self.assertEqual(sorted(self.daemon.removed), ["u0001-friend", "u0002-laptop"])
        row = self.desk.db.execute("SELECT status FROM accounts").fetchone()
        self.assertEqual(row["status"], "revoked")
        rows = self.desk.db.execute("SELECT status FROM peers").fetchall()
        self.assertTrue(all(r["status"] == "removed" for r in rows))

    def test_a_never_redeemed_device_ticket_is_swept_clean(self):
        token = self._token()
        self.desk.add_device({"token": token, "name": "laptop"})
        self.daemon.missing_peers = ["u0002-laptop"]
        self.desk.db.execute("UPDATE accounts SET expires='2000-01-01'")
        actions = self.desk.sweep_once()
        self.assertEqual(actions[0]["reason"], "expired")
        self.assertNotIn("error", actions[0])
        row = self.desk.db.execute("SELECT status FROM accounts").fetchone()
        self.assertEqual(row["status"], "expired")

    def test_a_failed_device_mint_leaves_no_orphan_row(self):
        token = self._token()
        self.daemon._refuse = True
        code, _ = self.desk.add_device({"token": token, "name": "laptop"})
        self.assertEqual(code, 502)
        self.assertEqual(
            self.desk.db.execute(
                "SELECT COUNT(*) FROM peers WHERE status='active'").fetchone()[0], 1)


class VoucherTests(DeskTestCase):
    """POST /api/voucher — a code's payload applied to an existing account,
    additive: days extend expiry, bytes grow the shared cap, plan relabels."""

    def _token(self):
        _, payload = self.signup()
        return payload["token"]

    def test_a_voucher_extends_the_plan_additively(self):
        token = self._token()
        _, minted = self.desk._mint_code({"days": 30, "bytes": 5000, "plan": "plus"})
        code, _ = self.desk.voucher({"token": token, "code": minted["code"]})
        self.assertEqual(code, 200)
        row = self.desk.db.execute("SELECT * FROM accounts").fetchone()
        self.assertEqual(row["bytes_cap"], 1000 + 5000)
        self.assertEqual(row["plan"], "plus")
        expected = (datetime.date.fromisoformat(row["expires"])
                    - datetime.timedelta(days=30))
        self.assertEqual(expected, datetime.date.fromisoformat(self.desk._trial_expiry()))
        code_row = self.desk.db.execute(
            "SELECT used_by FROM codes WHERE code=?", (minted["code"],)).fetchone()
        self.assertEqual(code_row["used_by"], "u0001-friend")

    def test_a_voucher_only_applies_the_parts_a_code_carries(self):
        token = self._token()
        _, minted = self.desk._mint_code({"bytes": 9000})
        code, _ = self.desk.voucher({"token": token, "code": minted["code"]})
        self.assertEqual(code, 200)
        row = self.desk.db.execute("SELECT * FROM accounts").fetchone()
        self.assertEqual(row["bytes_cap"], 10000)
        self.assertEqual(row["plan"], "trial")
        self.assertEqual(row["expires"], self.desk._trial_expiry())

    def test_an_unknown_voucher_code_is_refused(self):
        token = self._token()
        code, payload = self.desk.voucher({"token": token, "code": "not-a-code"})
        self.assertEqual(code, 403)
        self.assertIn("invite-only", payload["error"])

    def test_a_used_code_cannot_voucher_twice(self):
        _, minted = self.desk._mint_code({"days": 30})
        self.signup(code=minted["code"], name="first")
        token = self._token()
        code, payload = self.desk.voucher({"token": token, "code": minted["code"]})
        self.assertEqual(code, 403)
        self.assertIn("already used", payload["error"])

    def test_a_voucher_needs_an_active_account(self):
        token = self._token()
        self.desk.admin("/api/admin/revoke-account",
                        {"admin_token": "admin-secret", "peer": "u0001-friend"})
        _, minted = self.desk._mint_code({"days": 30})
        code, payload = self.desk.voucher({"token": token, "code": minted["code"]})
        self.assertEqual(code, 403)
        self.assertIn("revoked", payload["error"])

    def test_a_payload_less_code_has_nothing_to_grant_and_is_not_burned(self):
        token = self._token()
        _, minted = self.desk._mint_code({})
        code, payload = self.desk.voucher({"token": token, "code": minted["code"]})
        self.assertEqual(code, 400)
        self.assertIn("nothing to grant", payload["error"])
        row = self.desk.db.execute(
            "SELECT used_by FROM codes WHERE code=?", (minted["code"],)).fetchone()
        self.assertIsNone(row["used_by"])

    def test_a_voucher_redeems_once_under_a_race(self):
        token = self._token()
        _, minted = self.desk._mint_code({"days": 30, "bytes": 5000})
        results = []
        threads = [threading.Thread(
            target=lambda: results.append(
                self.desk.voucher({"token": token, "code": minted["code"]})[0]))
            for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results), [200, 403])
        row = self.desk.db.execute("SELECT bytes_cap FROM accounts").fetchone()
        self.assertEqual(row["bytes_cap"], 6000)


class AdminTests(DeskTestCase):

    def test_a_wrong_admin_token_is_refused(self):
        code, payload = self.desk.admin("/api/admin/peers", {"admin_token": "wrong"})
        self.assertEqual(code, 403)

    def test_a_missing_admin_token_is_refused(self):
        self.assertEqual(self.desk.admin("/api/admin/peers", {})[0], 403)

    def test_minting_a_code_registers_it(self):
        code, payload = self.desk.admin("/api/admin/code", {"admin_token": "admin-secret"})
        self.assertEqual(code, 200)
        self.assertTrue(self.desk.db.execute(
            "SELECT 1 FROM codes WHERE code=?", (payload["code"],)).fetchone())

    def test_setting_a_plan_changes_the_row(self):
        _, signup_payload = self.signup()
        peer = signup_payload["peer"]
        code, _ = self.desk.admin("/api/admin/plan", {
            "admin_token": "admin-secret", "peer": peer, "bytes_cap": 42})
        self.assertEqual(code, 200)
        self.assertEqual(self.desk.db.execute(
            "SELECT bytes_cap FROM accounts WHERE peer=?", (peer,)).fetchone()[0], 42)

    def test_an_account_can_be_reinstated(self):
        # The way back after a quota fired on a mis-set cap.
        _, signup_payload = self.signup()
        peer = signup_payload["peer"]
        self.desk.db.execute("UPDATE accounts SET status='overquota' WHERE peer=?", (peer,))
        code, _ = self.desk.admin("/api/admin/plan", {
            "admin_token": "admin-secret", "peer": peer, "status": "active"})
        self.assertEqual(code, 200)
        self.assertEqual(self.desk.db.execute(
            "SELECT status FROM accounts WHERE peer=?", (peer,)).fetchone()[0], "active")

    def test_an_unknown_status_is_refused(self):
        _, signup_payload = self.signup()
        code, payload = self.desk.admin("/api/admin/plan", {
            "admin_token": "admin-secret", "peer": signup_payload["peer"], "status": "banished"})
        self.assertEqual(code, 400)

    def test_adopting_an_existing_peer_registers_it(self):
        code, payload = self.desk.admin("/api/admin/adopt", {
            "admin_token": "admin-secret", "peer": "existing-peer"})
        self.assertEqual(code, 200)
        self.assertEqual(self.daemon.minted, [])  # adopted, not created
        self.assertEqual(self.desk.db.execute(
            "SELECT peer FROM accounts WHERE peer='existing-peer'").fetchone()[0], "existing-peer")

    def test_adopting_the_same_peer_twice_is_refused(self):
        self.desk.admin("/api/admin/adopt", {"admin_token": "admin-secret", "peer": "p"})
        code, _ = self.desk.admin("/api/admin/adopt", {"admin_token": "admin-secret", "peer": "p"})
        self.assertEqual(code, 409)

    def test_revoking_removes_the_peer(self):
        _, signup_payload = self.signup()
        peer = signup_payload["peer"]
        code, _ = self.desk.admin("/api/admin/revoke", {
            "admin_token": "admin-secret", "peer": peer})
        self.assertEqual(code, 200)
        self.assertEqual(self.daemon.removed, [peer])

    def test_an_unknown_admin_endpoint_is_not_found(self):
        code, _ = self.desk.admin("/api/admin/nope", {"admin_token": "admin-secret"})
        self.assertEqual(code, 404)


if __name__ == "__main__":
    unittest.main()
