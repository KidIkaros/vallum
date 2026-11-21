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
import re
import shlex
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
describe_devices = desk_module.describe_devices
DEVICE_STATES = desk_module.DEVICE_STATES
SESSION_LIVE_SECONDS = desk_module.SESSION_LIVE_SECONDS
token_digest = desk_module.token_digest


class FakeDaemon(desk_module.Daemon):
    """A daemon that is a dictionary with a method or two."""

    def __init__(self, counters=None, refuse=False, refuse_remove=False, liveness=None,
                 refuse_liveness=False, refuse_counters=False):
        self._counters = counters or {}
        self._refuse = refuse
        self._refuse_remove = refuse_remove
        self._liveness = liveness or {}
        self._refuse_liveness = refuse_liveness
        self._refuse_counters = refuse_counters
        self.removed = []
        self.minted = []
        self.pins = {}
        self.rotated = []

    def mint_ticket(self, peer, public_key=None):
        if self._refuse:
            raise RuntimeError("the daemon said no")
        self.minted.append(peer)
        self.pins[peer] = public_key
        return f"vallum1-join:203.0.113.9:51922/{peer}/deadbeef/token/fingerprint"

    def mint_sealed_ticket(self, peer, public_key, seal_aad):
        if self._refuse:
            raise RuntimeError("the daemon said no")
        self.minted.append(peer)
        self.pins[peer] = public_key
        if not hasattr(self, "sealed_aads"):
            self.sealed_aads = {}
        self.sealed_aads[peer] = seal_aad
        return {"sealed_ticket": {"kem_ct": "aa", "nonce": "bb", "ct": "cc"},
                "seal_aad": seal_aad, "join": "203.0.113.9:51922",
                "fingerprint": "fp", "name": peer, "id": "deadbeef",
                "expires_in_secs": 900}

    def counters(self):
        if self._refuse_counters:
            raise RuntimeError("the daemon did not answer")
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

    def rotate(self, peer, public_key):
        if getattr(self, "_refuse_rotate", False):
            raise RuntimeError("the daemon said no")
        if peer in getattr(self, "missing_peers", ()):
            raise RuntimeError(f"vallum: no peer named `{peer}`")
        self.rotated.append((peer, public_key))
        report = {"fingerprint": f"fp-{peer}", "applied": True, "finalized": True}
        if getattr(self, "_refuse_finalize", False):
            report["finalized"] = False
            report["finalize_error"] = "vallum peer finalize: the daemon said no"
        return report


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

    def signup(self, code="friend-code-1"):
        return self.desk.signup({"code": code})

    def account_with_device(self, code="friend-code-1", name="friend"):
        """An account plus its first device — the shape most tests need now
        that signup creates the account alone (ADR-0047). Returns both
        payloads; the device peer is `u0001-<name>`."""
        _, account = self.signup(code=code)
        _, device = self.desk.add_device({"token": account["token"], "name": name})
        return account, device


class DevicePullSealTests(DeskTestCase):
    """ADR-0049: device-pull — the desk relays a ticket sealed to the device's
    key, never the plaintext; the AAD binds the blob to one account + device."""

    PUB = "vallum1:0003:" + "ab" * 64 + ":-"

    def test_seal_returns_ciphertext_not_the_ticket(self):
        _, account = self.signup()
        code, payload = self.desk.add_device(
            {"token": account["token"], "name": "laptop",
             "public_key": self.PUB, "seal": True})
        self.assertEqual(code, 200)
        self.assertIn("sealed_ticket", payload)
        self.assertNotIn("ticket", payload)
        self.assertNotIn("connect", payload)
        self.assertTrue(payload["seal_aad"].endswith("||" + self.PUB))
        self.assertTrue(payload["pinned"])
        self.assertEqual(self.daemon.sealed_aads[payload["peer"]], payload["seal_aad"])

    def test_seal_without_a_public_key_is_refused(self):
        _, account = self.signup()
        code, payload = self.desk.add_device(
            {"token": account["token"], "name": "laptop", "seal": True})
        self.assertEqual(code, 400)
        self.assertIn("public_key", payload["error"])

    def test_seal_still_enforces_the_device_cap(self):
        _, account = self.signup()
        for i in range(self.config.device_cap):
            code, _ = self.desk.add_device(
                {"token": account["token"], "name": f"d{i}",
                 "public_key": self.PUB, "seal": True})
            self.assertEqual(code, 200)
        code, _ = self.desk.add_device(
            {"token": account["token"], "name": "over",
             "public_key": self.PUB, "seal": True})
        self.assertEqual(code, 429)

    def test_unsealed_add_device_still_returns_the_plain_ticket(self):
        _, account = self.signup()
        code, payload = self.desk.add_device(
            {"token": account["token"], "name": "laptop", "public_key": self.PUB})
        self.assertEqual(code, 200)
        self.assertIn("ticket", payload)
        self.assertNotIn("sealed_ticket", payload)


class ResetTokenTests(DeskTestCase):
    """ADR-0047 Q3: the account number is shown once at signup and there is no
    self-service recovery — the operator is the recovery path. reset-token
    issues a fresh number and retires the old, leaving the account's devices,
    plan, quota and expiry untouched."""

    def test_reset_by_token_issues_a_new_number_and_retires_the_old(self):
        _, account = self.signup()
        old = account["token"]
        code, payload = self.desk.admin(
            "/api/admin/reset-token",
            {"admin_token": "admin-secret", "token": old})
        self.assertEqual(code, 200)
        new = payload["token"]
        self.assertNotEqual(new, old)
        self.assertEqual(len(new), 32)
        # The old number is the bearer credential: it stops working at once.
        self.assertEqual(self.desk.status(old)[0], 404)
        self.assertEqual(self.desk.status(new)[0], 200)

    def test_reset_by_peer_addressing(self):
        account, device = self.account_with_device()
        code, payload = self.desk.admin(
            "/api/admin/reset-token",
            {"admin_token": "admin-secret", "peer": device["peer"]})
        self.assertEqual(code, 200)
        self.assertNotEqual(payload["token"], account["token"])
        self.assertEqual(self.desk.status(payload["token"])[0], 200)

    def test_reset_preserves_devices_plan_and_quota(self):
        account, device = self.account_with_device()
        self.desk.admin(
            "/api/admin/plan",
            {"admin_token": "admin-secret", "token": account["token"],
             "plan": "plus", "bytes_cap": 5000})
        code, payload = self.desk.admin(
            "/api/admin/reset-token",
            {"admin_token": "admin-secret", "token": account["token"]})
        self.assertEqual(code, 200)
        _, status = self.desk.status(payload["token"])
        self.assertEqual(status["peers"], [device["peer"]])
        row = self.desk.db.execute(
            "SELECT plan, bytes_cap, status FROM accounts WHERE token=?",
            (token_digest(payload["token"]),)).fetchone()
        self.assertEqual(row["plan"], "plus")
        self.assertEqual(row["bytes_cap"], 5000)
        self.assertEqual(row["status"], "active")

    def test_reset_unknown_account_is_404(self):
        code, _ = self.desk.admin(
            "/api/admin/reset-token",
            {"admin_token": "admin-secret", "peer": "nobody"})
        self.assertEqual(code, 404)

    def test_reset_requires_the_admin_token(self):
        _, account = self.signup()
        code, _ = self.desk.admin(
            "/api/admin/reset-token",
            {"admin_token": "wrong", "token": account["token"]})
        self.assertEqual(code, 403)

    def test_missing_admin_token_is_never_admin(self):
        """A request that omits admin_token must not be admin — the empty
        string compare_digest would otherwise match an empty stored token."""
        self.desk.config.admin_token = ""
        code, _ = self.desk.admin("/api/admin/peers", {})
        self.assertEqual(code, 403)


class AdminTokenFileTests(unittest.TestCase):
    """admin_token_from: an existing-but-empty file is regenerated, never
    returned — "" would open the admin surface to requests without a token."""

    def test_empty_file_is_regenerated_not_returned(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "admin-token")
            open(path, "w").close()
            token = desk_module.admin_token_from(path)
            self.assertTrue(token, "an empty file must yield a fresh token")
            with open(path) as f:
                self.assertEqual(f.read().strip(), token)

    def test_created_file_is_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "admin-token")
            desk_module.admin_token_from(path)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


class StateFileModeTests(DeskTestCase):
    """The account database holds the only credential the desk issues."""

    def test_database_is_not_world_readable(self):
        # sqlite3 creates the file 0644 under the default umask, and every
        # account token would then be readable by any local account — the CI
        # runner user on the same host included. `open_database` tightens it.
        mode = os.stat(self.config.state).st_mode & 0o777
        self.assertEqual(mode, 0o600, f"{self.config.state} is mode {mode:o}, not 600")


class SignupTests(DeskTestCase):
    """ADR-0047: signup creates an account, never a device. The device name
    belongs to the client-driven enrolment (`add_device`), not the web form —
    the durable account, not the ephemeral ticket, is the centre of the flow."""

    def test_signup_creates_an_account_without_a_device(self):
        code, payload = self.signup()
        self.assertEqual(code, 200)
        self.assertTrue(payload["token"])
        for gone in ("ticket", "peer", "connect"):
            self.assertNotIn(gone, payload)
        row = self.desk.db.execute("SELECT * FROM accounts").fetchone()
        self.assertIsNone(row["peer"])
        self.assertEqual(row["status"], "active")
        self.assertEqual(
            self.desk.db.execute("SELECT COUNT(*) FROM peers").fetchone()[0], 0)
        self.assertEqual(self.daemon.minted, [])

    def test_signup_needs_no_daemon(self):
        # Creating the account is desk-only: the daemon is asked when a device
        # enrols. A down daemon must not stop signup — that is the whole point
        # of centring the flow on the durable account.
        self.daemon._refuse = True
        self.assertEqual(self.signup()[0], 200)

    def test_a_device_name_at_signup_is_refused_with_guidance(self):
        # The old shape (code + device name) is refused, not silently
        # reinterpreted: the caller is told where the device name lives now.
        code, payload = self.desk.signup({"code": "friend-code-1", "name": "laptop"})
        self.assertEqual(code, 400)
        self.assertIn("device", payload["error"])
        self.assertEqual(self.daemon.minted, [])
        # The refusal does not burn the code.
        self.assertEqual(self.signup()[0], 200)

    def test_an_unknown_code_is_refused(self):
        code, payload = self.signup(code="not-a-code")
        self.assertEqual(code, 403)
        self.assertIn("invite-only", payload["error"])
        self.assertEqual(self.daemon.minted, [])

    def test_a_code_is_single_use(self):
        self.assertEqual(self.signup()[0], 200)
        code, payload = self.signup()
        self.assertEqual(code, 403)
        self.assertIn("already used", payload["error"])

    def test_accounts_are_labelled_distinctly(self):
        # Fourteen rows labelled "account" are fourteen unreadable rows; the
        # label carries the account id so the operator's listing can tell
        # them apart without exposing the token as a name.
        self.signup()
        self.signup(code="friend-code-2")
        labels = [r["label"] for r in self.desk.db.execute(
            "SELECT label FROM accounts ORDER BY id")]
        self.assertEqual(len(set(labels)), 2)
        self.assertTrue(all(label for label in labels))

    def test_signup_does_not_consume_a_peer_number(self):
        # Peer numbers count devices, not accounts: two accounts and then one
        # device enrols as u0001, not u0003. The old flow burned a peer slot
        # (and a daemon invite) on every signup, even one that never joined.
        _, first = self.signup()
        self.signup(code="friend-code-2")
        _, device = self.desk.add_device({"token": first["token"], "name": "laptop"})
        self.assertEqual(device["peer"], "u0001-laptop")

    def test_a_failed_signup_write_leaves_no_half_account(self):
        # The account row, its label and the signup count are one transaction:
        # a failure part-way must not leave an account behind (and, on the
        # coded path, a burned code with no account to show for it).
        self.config.open_signup = True
        def boom(ip):
            raise RuntimeError("disk on fire")
        self.desk._count_signup = boom
        with self.assertRaises(RuntimeError):
            self.desk.signup({})
        self.assertEqual(
            self.desk.db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0], 0)
        self.assertEqual(
            self.desk.db.execute("SELECT COUNT(*) FROM signups").fetchone()[0], 0)


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

    def test_a_pinned_mint_passes_the_public_key_to_peer_invite(self):
        # The pin turns the ticket from a bearer credential into a
        # registration for a key the client already holds (ADR-0047 §3):
        # `peer invite --public-key LINE`. The line is one argv element —
        # never shell input — and the ticket still comes from the JSON field.
        line = "vallum1:0003:" + "ab" * 32 + ":-"
        with tempfile.TemporaryDirectory() as tempdir:
            cli = os.path.join(tempdir, "vallum")
            args_file = os.path.join(tempdir, "args")
            with open(cli, "w") as f:
                f.write("#!/bin/sh\nprintf '%s\\n' \"$@\" > " + shlex.quote(args_file) + "\n"
                        "printf '%s\\n' "
                        "'{\"ticket\":\"vallum1-join:203.0.113.9:51922/laptop/id/token/fp\"}'\n")
            os.chmod(cli, 0o755)
            daemon = desk_module.DaemonCli("/etc/vallum/server.toml", cli=cli)
            ticket = daemon.mint_ticket("laptop", public_key=line)
            self.assertEqual(ticket, "vallum1-join:203.0.113.9:51922/laptop/id/token/fp")
            with open(args_file) as f:
                argv = f.read().splitlines()
            self.assertEqual(argv[:4], ["peer", "invite", "laptop", "--json"])
            self.assertEqual(argv[argv.index("--public-key") + 1], line)

    def test_an_unpinned_mint_sends_no_public_key_flag(self):
        # The web account page enrols without a pre-shared public line: the
        # client generates its key at join time. That path must stay exactly
        # `peer invite <name> --json` — no empty pin, which the daemon would
        # read as a line to validate.
        with tempfile.TemporaryDirectory() as tempdir:
            cli = os.path.join(tempdir, "vallum")
            args_file = os.path.join(tempdir, "args")
            with open(cli, "w") as f:
                f.write("#!/bin/sh\nprintf '%s\\n' \"$@\" > " + shlex.quote(args_file) + "\n"
                        "printf '%s\\n' '{\"ticket\":\"vallum1-join:h:1/n/i/t/f\"}'\n")
            os.chmod(cli, 0o755)
            daemon = desk_module.DaemonCli("/etc/vallum/server.toml", cli=cli)
            daemon.mint_ticket("laptop")
            with open(args_file) as f:
                argv = f.read().splitlines()
            self.assertNotIn("--public-key", argv)

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

    def _cli_recording_calls(self, tempdir, finalize_fails=False, rotate_body=None):
        """A fake `vallum` that appends each call's argv (CALL-marked blocks)
        and answers `peer rotate` with `rotate_body`."""
        cli = os.path.join(tempdir, "vallum")
        args_file = os.path.join(tempdir, "args")
        body = rotate_body if rotate_body is not None else '{"fingerprint":"fp123","applied":true}'
        finalize_branch = ('echo "finalize: boom" >&2; exit 1' if finalize_fails
                           else "printf '%s\\n' '{\"retired\":true}'")
        with open(cli, "w") as f:
            f.write("#!/bin/sh\n"
                    "printf 'CALL\\n' >> " + shlex.quote(args_file) + "\n"
                    "printf '%s\\n' \"$@\" >> " + shlex.quote(args_file) + "\n"
                    "if [ \"$1 $2\" = 'peer finalize' ]; then " + finalize_branch + "; fi\n"
                    "printf '%s\\n' " + shlex.quote(body) + "\n")
        os.chmod(cli, 0o755)
        return desk_module.DaemonCli("/etc/vallum/server.toml", cli=cli), args_file

    def test_rotation_passes_the_line_to_peer_rotate_then_finalizes(self):
        # The port's contract with the CLI: the line rides as ONE argv
        # element to `peer rotate --public-key … --json`, then `peer
        # finalize` retires the old key (ADR-0047 §4). The fingerprint and
        # applied verdict come from the JSON field, never a text scrape.
        line = "vallum1:0003:" + "ab" * 32 + ":-"
        with tempfile.TemporaryDirectory() as tempdir:
            daemon, args_file = self._cli_recording_calls(tempdir)
            report = daemon.rotate("laptop", line)
            self.assertEqual(report, {"fingerprint": "fp123", "applied": True,
                                      "finalized": True})
            with open(args_file) as f:
                blocks = f.read().split("CALL\n")[1:]
            self.assertEqual(len(blocks), 2)
            rotate_argv = blocks[0].splitlines()
            self.assertEqual(rotate_argv[:6],
                             ["peer", "rotate", "laptop", "--public-key", line, "--json"])
            self.assertEqual(rotate_argv[-2:], ["--config", "/etc/vallum/server.toml"])
            finalize_argv = blocks[1].splitlines()
            self.assertEqual(finalize_argv[:3], ["peer", "finalize", "laptop"])

    def test_a_failed_finalize_reports_finalized_false(self):
        # The rotation already happened when finalize fails: the port must
        # report both facts, not raise — a 502 would misname what did.
        line = "vallum1:0003:" + "ab" * 32 + ":-"
        with tempfile.TemporaryDirectory() as tempdir:
            daemon, _ = self._cli_recording_calls(tempdir, finalize_fails=True)
            report = daemon.rotate("laptop", line)
            self.assertIs(report["finalized"], False)
            self.assertIn("boom", report["finalize_error"])
            self.assertEqual(report["fingerprint"], "fp123")

    def test_rotate_json_that_does_not_parse_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tempdir:
            daemon, _ = self._cli_recording_calls(tempdir, rotate_body="not json")
            with self.assertRaises(RuntimeError):
                daemon.rotate("laptop", "vallum1:0003:" + "ab" * 32 + ":-")

    def test_rotate_json_of_wrong_shape_fails_loudly(self):
        # Valid JSON of the wrong shape is the same failure as unparseable
        # JSON: a loud RuntimeError, not an AttributeError behind a 500.
        # The real `Rotated` report always carries a fingerprint string.
        line = "vallum1:0003:" + "ab" * 32 + ":-"
        for body in ("null", "[]", '"ok"', "{}", '{"fingerprint": null}'):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as tempdir:
                daemon, _ = self._cli_recording_calls(tempdir, rotate_body=body)
                with self.assertRaises(RuntimeError):
                    daemon.rotate("laptop", line)

    def test_mint_ticket_json_of_wrong_shape_fails_loudly(self):
        # Same shape guard on the invite path (the gap pre-dated rotate).
        for body in ("null", "[]", '"ok"'):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as tempdir:
                cli = os.path.join(tempdir, "vallum")
                with open(cli, "w") as f:
                    f.write("#!/bin/sh\nprintf '%s\\n' " + shlex.quote(body) + "\n")
                os.chmod(cli, 0o755)
                daemon = desk_module.DaemonCli("/etc/vallum/server.toml", cli=cli)
                with self.assertRaises(RuntimeError):
                    daemon.mint_ticket("laptop")


class StatusTests(DeskTestCase):

    def test_status_reports_the_bytes_used_for_the_account_peer(self):
        account, device = self.account_with_device()
        peer = device["peer"]
        # The daemon keys its counters by peer NAME. A reader that looked them
        # up by fingerprint would report zero here — which is how a quota
        # stops firing while the expiry path keeps working.
        self.daemon._counters = {peer: 23838}
        # The column holds a digest (v7): status() hashes what it is given, so
        # the plaintext from signup is the only thing that resolves.
        code, payload = self.desk.status(account["token"])
        self.assertEqual(code, 200)
        self.assertEqual(payload["bytes_used"], 23838)

    def test_an_unknown_token_is_not_found(self):
        code, payload = self.desk.status("nope")
        self.assertEqual(code, 404)


class OrphanSweepTests(DeskTestCase):
    """A peer row under a non-active account is unreachable, so the sweep clears it.

    The sweep only visits active accounts, so a row left `active` under a revoked
    one is never revisited. Ten accumulated on the reference desk, and
    `vallum-desk-admin devices` reported fourteen active devices against four
    active accounts.
    """

    def _revoke_account_directly(self, token):
        """Revoke the account row without the peer cleanup — the historical state
        the sweep has to recover from."""
        self.desk.db.execute(
            "UPDATE accounts SET status='revoked' WHERE token=?", (token_digest(token),))

    def test_a_peer_under_a_revoked_account_is_marked_removed(self):
        account, _ = self.account_with_device()
        self._revoke_account_directly(account["token"])
        actions = self.desk.sweep_once()
        self.assertEqual(
            [a for a in actions if a.get("reason") == "orphaned"],
            [{"peer": "u0001-friend", "reason": "orphaned"}])
        row = self.desk.db.execute(
            "SELECT status FROM peers WHERE peer='u0001-friend'").fetchone()
        self.assertEqual(row["status"], "removed")

    def test_the_sweep_asks_the_daemon_to_remove_the_orphan(self):
        # An orphaned row can be a peer still live on the server and no longer
        # enforced, which is worse than a stale row. Marking the row alone would
        # leave that peer carrying traffic.
        account, _ = self.account_with_device()
        self._revoke_account_directly(account["token"])
        self.desk.sweep_once()
        self.assertIn("u0001-friend", self.daemon.removed)

    def test_a_peer_the_daemon_never_had_is_already_in_the_goal_state(self):
        # The normal case: a ticket nobody redeemed has no peer on the server.
        account, _ = self.account_with_device()
        self.daemon.missing_peers = ("u0001-friend",)
        self._revoke_account_directly(account["token"])
        actions = self.desk.sweep_once()
        self.assertEqual(
            [a for a in actions if a.get("reason") == "orphaned"],
            [{"peer": "u0001-friend", "reason": "orphaned"}])

    def test_a_peer_that_cannot_be_removed_stays_active_for_the_next_pass(self):
        # If the daemon refuses for a reason other than "no such peer", the row
        # must stay active: marking it removed would make an enforced-nowhere
        # peer look handled, and nothing would ever retry it.
        account, _ = self.account_with_device()
        self._revoke_account_directly(account["token"])
        self.desk.daemon = FakeDaemon(refuse_remove=True)
        actions = self.desk.sweep_once()
        self.assertEqual([a for a in actions if a.get("reason") == "orphaned"], [])
        row = self.desk.db.execute(
            "SELECT status FROM peers WHERE peer='u0001-friend'").fetchone()
        self.assertEqual(row["status"], "active")

    def test_a_peer_under_an_active_account_is_left_alone(self):
        self.account_with_device()
        self.desk.sweep_once()
        row = self.desk.db.execute(
            "SELECT status FROM peers WHERE peer='u0001-friend'").fetchone()
        self.assertEqual(row["status"], "active")


class EnforcementTests(DeskTestCase):

    def account_row(self, token):
        return self.desk.db.execute("SELECT * FROM accounts WHERE token=?", (token_digest(token),)).fetchone()

    def test_an_expired_account_loses_its_peer(self):
        account, device = self.account_with_device()
        peer = device["peer"]
        self.desk.db.execute("UPDATE accounts SET expires='2020-01-01' WHERE token=?",
                             (token_digest(account["token"]),))
        actions = self.desk.sweep_once()
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["reason"], "expired")
        self.assertEqual(self.daemon.removed, [peer])
        self.assertEqual(self.account_row(account["token"])["status"], "expired")

    def test_an_account_over_its_byte_cap_loses_its_peer(self):
        account, device = self.account_with_device()
        self.daemon._counters = {device["peer"]: 5000}  # cap is 1000
        actions = self.desk.sweep_once()
        self.assertEqual(actions[0]["reason"], "overquota")
        self.assertEqual(self.daemon.removed, [device["peer"]])

    def test_a_healthy_account_is_left_alone(self):
        _, device = self.account_with_device()
        self.daemon._counters = {device["peer"]: 10}
        self.assertEqual(self.desk.sweep_once(), [])
        self.assertEqual(self.daemon.removed, [])

    def test_an_account_expiring_today_is_expired(self):
        # Inclusive: "expires 2026-11-16" means it is already spent on the
        # 16th, not at the end of it.
        account, _ = self.account_with_device()
        today = desk_module.datetime.date.today().isoformat()
        self.desk.db.execute("UPDATE accounts SET expires=? WHERE token=?",
                             (today, token_digest(account["token"])))
        self.assertEqual(self.desk.sweep_once()[0]["reason"], "expired")

    def test_a_failed_removal_is_retried_instead_of_marked_revoked(self):
        # The row is what the next sweep reads, so marking it before the peer
        # is actually gone hides a live peer from every future pass.
        account, device = self.account_with_device()
        peer = device["peer"]
        self.desk.db.execute("UPDATE accounts SET expires='2020-01-01' WHERE token=?",
                             (token_digest(account["token"]),))
        self.daemon._refuse_remove = True
        action = self.desk.sweep_once()[0]
        self.assertIn("error", action)
        self.assertEqual(self.account_row(account["token"])["status"], "active")
        self.daemon._refuse_remove = False
        self.assertEqual(self.desk.sweep_once()[0]["reason"], "expired")
        self.assertEqual(self.account_row(account["token"])["status"], "expired")
        self.assertEqual(self.daemon.removed, [peer])

    def test_a_peer_that_was_never_created_marks_the_account_without_retrying(self):
        # A ticket minted but never redeemed leaves no peer to remove: "no
        # peer named" is the goal state already holding, not a failure, and a
        # row that retries it forever would never finish sweeping.
        account, device = self.account_with_device()
        self.desk.db.execute("UPDATE accounts SET expires='2020-01-01' WHERE token=?",
                             (token_digest(account["token"]),))
        self.daemon.missing_peers = {device["peer"]}
        action = self.desk.sweep_once()[0]
        self.assertNotIn("error", action)
        self.assertEqual(action["reason"], "expired")
        self.assertEqual(self.account_row(account["token"])["status"], "expired")


class OnDemandTests(DeskTestCase):
    """Open signup: no invite code, bounded per IP and by capacity."""

    def open_desk(self):
        self.config.open_signup = True
        self.config.open_trial_bytes = 500
        self.config.max_active_accounts = 2
        self.config.signup_ip_day_limit = 2

    def test_open_mode_signs_up_without_a_code(self):
        self.open_desk()
        code, payload = self.desk.signup({}, client_ip="198.51.100.9")
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
        first = self.desk.signup({}, client_ip="198.51.100.9")
        second = self.desk.signup({}, client_ip="198.51.100.9")
        third = self.desk.signup({}, client_ip="198.51.100.9")
        self.assertEqual(first[0], 200)
        self.assertEqual(second[0], 200)
        self.assertEqual(third[0], 429)
        # a different address is not affected by this one's history
        other = self.desk.signup({}, client_ip="198.51.100.10")
        self.assertEqual(other[0], 200)

    def test_capacity_queues_an_open_signup_instead_of_refusing_it(self):
        """Account then code: space gates entitlement, never existence — at
        capacity the account persists pending, retained for activation."""
        self.open_desk()
        for n in range(2):
            self.assertEqual(
                self.desk.signup({}, client_ip=f"198.51.100.{n}")[0], 200)
        code, payload = self.desk.signup({}, client_ip="198.51.100.9")
        self.assertEqual(code, 200)
        self.assertEqual(payload["status"], "pending")
        self.assertEqual(payload["bytes_cap"], 0)
        self.assertIn("token", payload)  # the account exists — it has a number

    def test_a_pending_account_cannot_add_devices_until_activated(self):
        self.open_desk()
        self.config.max_active_accounts = 0  # every open signup queues
        _, account = self.desk.signup({}, client_ip="198.51.100.9")
        code, payload = self.desk.add_device(
            {"token": account["token"], "name": "laptop"})
        self.assertEqual(code, 403)
        self.assertIn("queued", payload["error"])

    def test_a_voucher_activates_a_queued_account_immediately(self):
        self.open_desk()
        self.config.max_active_accounts = 0
        _, account = self.desk.signup({}, client_ip="198.51.100.9")
        _, minted = self.desk._mint_code({"days": 30, "bytes": 5000, "plan": "plus"})
        code, applied = self.desk.voucher(
            {"token": account["token"], "code": minted["code"]})
        self.assertEqual(code, 200)
        self.assertEqual(applied["plan"], "plus")
        self.assertEqual(applied["bytes_cap"], 5000)
        row = self.desk.db.execute(
            "SELECT status FROM accounts WHERE label=?",
            (f"account-1",)).fetchone()
        self.assertEqual(row["status"], "active")
        # and devices join now
        code, _ = self.desk.add_device({"token": account["token"], "name": "laptop"})
        self.assertEqual(code, 200)

    def test_the_sweep_promotes_queued_accounts_as_space_frees(self):
        self.open_desk()
        self.config.max_active_accounts = 1
        _, first = self.desk.signup({}, client_ip="198.51.100.1")
        _, queued = self.desk.signup({}, client_ip="198.51.100.2")
        self.assertEqual(queued["status"], "pending")
        # space frees — the first account leaves active
        self.desk.db.execute(
            "UPDATE accounts SET status='revoked' WHERE id=1")
        actions = self.desk.sweep_once()
        self.assertTrue(any("promoted" in a for a in actions))
        row = self.desk.db.execute(
            "SELECT status, bytes_cap FROM accounts WHERE id=2").fetchone()
        self.assertEqual(row["status"], "active")
        self.assertEqual(row["bytes_cap"], 500)  # the open trial, minted fresh
        # the promoted account behaves like any signup
        code, _ = self.desk.add_device({"token": queued["token"], "name": "laptop"})
        self.assertEqual(code, 200)

    def test_closed_mode_still_refuses_without_a_code(self):
        code, payload = self.desk.signup({}, client_ip="198.51.100.9")
        self.assertEqual(code, 403)


class WireTestCase(DeskTestCase):
    """A desk behind a real loopback HTTP server — the wire seam, shared by
    the open-mode and closed-mode suites."""

    def setUp(self):
        super().setUp()
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


class HttpTests(WireTestCase):
    """The wire, not just the logic: a bad body is answered, never dropped.
    Open mode — the anonymous posture; closed mode has its own suite below."""

    def setUp(self):
        super().setUp()
        self.config.open_signup = True

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

    def test_the_index_asks_for_no_device_name(self):
        # ADR-0047: no device name on the web, ever. The form creates the
        # account; devices enrol from the account page, client-driven.
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=5) as r:
            page = r.read().decode()
        self.assertNotIn('name="name"', page)

    def test_the_devices_wire_carries_the_pin(self):
        # The API seam an agent uses (ADR-0047 §3): signup → devices with a
        # public line → a pinned ticket. The wire answers with the same
        # `pinned` verdict the logic does, and a bad line is a 400 on the
        # wire too — not a dropped connection.
        _, signup_body = self.post("/api/signup", '{"code":"friend-code-1"}',
                                   "application/json")
        token = json.loads(signup_body)["token"]
        line = "vallum1:0003:" + "cd" * 32 + ":-"
        status, body = self.post(
            "/api/devices",
            json.dumps({"token": token, "name": "agent", "public_key": line}),
            "application/json")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertIs(payload["pinned"], True)
        self.assertTrue(payload["ticket"].startswith("vallum1-join:"))
        self.assertEqual(self.daemon.pins[payload["peer"]], line)
        status, body = self.post(
            "/api/devices",
            json.dumps({"token": token, "name": "bad", "public_key": "nope"}),
            "application/json")
        self.assertEqual(status, 400)
        self.assertIn("public_key", json.loads(body)["error"])

    def test_the_rotate_wire_preserves_the_slot(self):
        # The API seam an agent uses (ADR-0047 §4): enrol a device, then
        # rotate its key over the wire — same peer, no new ticket, and a
        # bad line is a 400 on the wire too, not a dropped connection.
        _, signup_body = self.post("/api/signup", '{"code":"friend-code-1"}',
                                   "application/json")
        token = json.loads(signup_body)["token"]
        line = "vallum1:0003:" + "cd" * 32 + ":-"
        status, body = self.post(
            "/api/devices", json.dumps({"token": token, "name": "agent"}),
            "application/json")
        self.assertEqual(status, 200)
        peer = json.loads(body)["peer"]
        status, body = self.post(
            "/api/devices/rotate",
            json.dumps({"token": token, "peer": peer, "public_key": line}),
            "application/json")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["rotated"], peer)
        self.assertIs(payload["finalized"], True)
        self.assertNotIn("ticket", payload)  # rotation mints nothing
        self.assertEqual(self.daemon.rotated, [(peer, line)])
        status, body = self.post(
            "/api/devices/rotate",
            json.dumps({"token": token, "peer": peer, "public_key": "nope"}),
            "application/json")
        self.assertEqual(status, 400)
        self.assertIn("public_key", json.loads(body)["error"])

    def test_the_rotate_wire_answers_a_non_string_peer(self):
        # A list where a peer name belongs must be a 400 JSON answer on the
        # wire — not a sqlite bind error dropping a 500 (or the connection).
        _, signup_body = self.post("/api/signup", '{"code":"friend-code-1"}',
                                   "application/json")
        token = json.loads(signup_body)["token"]
        status, body = self.post(
            "/api/devices/rotate",
            json.dumps({"token": token, "peer": ["u0001-x"],
                        "public_key": "vallum1:0003:" + "cd" * 32 + ":-"}),
            "application/json")
        self.assertEqual(status, 400)
        self.assertIn("peer", json.loads(body)["error"])

    def test_the_form_path_answers_with_an_account_page(self):
        status, page = self.post("/signup", "", "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertIn("account number", page)
        self.assertNotIn("vallum1-join:", page)  # no ticket exists at signup

    def test_a_json_body_sent_as_a_form_is_named_as_the_mistake(self):
        # curl -d sends form-encoding by default; the desk must say so rather
        # than report "bad admin token" for a body it never parsed.
        status, page = self.post("/api/admin/sweep", '{"admin_token":"x"}',
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 500)
        self.assertIn("application/json", page)

    def test_the_json_api_still_works(self):
        status, body = self.post("/api/signup", "{}", "application/json")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["token"])
        self.assertNotIn("ticket", payload)

    def test_the_connect_uri_carries_the_desk_origin(self):
        # ADR-0046: the client records where its account lives from desk=<origin>
        # in the connect URI. The origin is https + the Host header the front
        # (Caddy) forwards — here, the loopback authority the request used.
        # The URI now rides the device ticket (signup has none).
        from urllib.parse import quote
        status, body = self.post("/api/signup", "{}", "application/json")
        self.assertEqual(status, 200)
        token = json.loads(body)["token"]
        status, body = self.post("/api/devices",
                                 json.dumps({"token": token, "name": "laptop"}),
                                 "application/json")
        self.assertEqual(status, 200)
        connect = json.loads(body)["connect"]
        origin = f"https://127.0.0.1:{self.port}"
        self.assertIn(f"&desk={quote(origin, safe='')}", connect)

    def test_the_ticket_pages_connect_button_carries_the_desk_origin(self):
        # The button fires the payload's connect URI — the same string the
        # JSON API returns, desk origin included, not a second derivation.
        from urllib.parse import quote
        status, body = self.post("/api/signup", "{}", "application/json")
        token = json.loads(body)["token"]
        status, page = self.post("/account/device", f"token={token}&name=laptop",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        origin = f"https://127.0.0.1:{self.port}"
        self.assertIn(f"&amp;desk={quote(origin, safe='')}", page)

    def test_the_connect_button_recovers_a_silent_click(self):
        # No client installed → the vallum:// click can produce nothing
        # visible. The page must name the recovery when the handoff never
        # happens: a hidden hint desk.js's blur-timeout reveals.
        status, body = self.post("/api/signup", "{}", "application/json")
        token = json.loads(body)["token"]
        status, page = self.post("/account/device", f"token={token}&name=laptop",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertIn('id="connect-fallback" hidden', page)
        self.assertIn("Nothing opened?", page)
        self.assertIn('data-fallback="connect-fallback"', page)
        self.assertIn('src="/desk.js"', page)

    def test_the_open_client_button_recovers_a_silent_click(self):
        # Same failure mode on the account handoff: no client → the
        # vallum://account click is invisible. The recovery says the
        # number alone is enough.
        status, page = self.post("/signup", "",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertIn('id="client-fallback" hidden', page)
        self.assertIn("Nothing opened?", page)
        self.assertIn('data-fallback="client-fallback"', page)
        self.assertIn('src="/desk.js"', page)

    def test_desk_js_carries_the_handoff_logic(self):
        # The strict-CSP script lives same-origin: the click handlers fire
        # data-uri, watch the handoff blur, and reveal the fallback.
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/desk.js",
                                    timeout=5) as r:
            js = r.read().decode()
        self.assertEqual(r.status, 200)
        self.assertIn("data-uri", js)
        self.assertIn("blur", js)
        self.assertIn("handed", js)
        self.assertIn("clipboard", js)

    def test_head_is_answered_not_refused(self):
        # Monitors HEAD: 501 read as "down" while the pages were fine.
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/",
                                     method="HEAD")
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertEqual(r.status, 200)

    def test_the_per_ip_limit_sees_the_visitor_behind_the_proxy(self):
        # The desk is loopback-only and fronted by Caddy. Reading
        # client_address would make every visitor 127.0.0.1 and turn the
        # per-IP limit into a global three-signups-a-day limit.
        self.config.signup_ip_day_limit = 1
        same = {"X-Forwarded-For": "198.51.100.9"}
        self.assertEqual(
            self.post("/api/signup", "{}", "application/json", same)[0], 200)
        self.assertEqual(
            self.post("/api/signup", "{}", "application/json", same)[0], 429)
        other = {"X-Forwarded-For": "198.51.100.10"}
        self.assertEqual(
            self.post("/api/signup", "{}", "application/json", other)[0], 200)


class ClosedModeHttpTests(WireTestCase):
    """Closed (invite-only) is the shipped default posture. The wire must
    render the code field, tell an empty code from an unknown one, and make
    the 15-minute ticket survivable (#27)."""

    def get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as r:
            return r.status, r.read().decode()

    def test_the_closed_index_renders_the_required_code_field(self):
        status, page = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("invite code", page)
        self.assertIn('<input name="code" required>', page)

    def test_an_empty_code_asks_for_the_code_not_an_unknown_one(self):
        # An empty field is a missing input, not a bad credential: "unknown
        # invite code" sent alpha users hunting for a code they never typed.
        status, page = self.post("/signup", "",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 403)
        self.assertIn("enter your invite code", page)
        self.assertNotIn("unknown invite code", page)

    def test_an_unknown_code_still_says_unknown(self):
        status, page = self.post("/signup", "code=not-a-code",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 403)
        self.assertIn("unknown invite code", page)
        self.assertNotIn("enter your invite code", page)

    def _signup_and_add_device(self, code="friend-code-1", name="friend"):
        """The closed-mode journey: code → account, then a device ticket."""
        status, body = self.post("/api/signup", json.dumps({"code": code}),
                                 "application/json")
        self.assertEqual(status, 200)
        token = json.loads(body)["token"]
        return self.post("/account/device", f"token={token}&name={name}",
                         "application/x-www-form-urlencoded")

    def test_the_ticket_page_states_the_fifteen_minute_window(self):
        # INVITE_TTL_SECS = 15 * 60 (crates/vallum/src/enroll.rs): the alpha's
        # 14 tickets / 0 handshakes were users who installed first and joined
        # after the ticket expired. The page must say the window out loud.
        # The ticket now comes from add-device, not signup — the window is a
        # property of the ticket, wherever it is minted.
        status, page = self._signup_and_add_device()
        self.assertEqual(status, 200)
        self.assertIn("15 minutes", page)

    def test_the_ticket_page_guides_an_expired_ticket_to_add_a_device(self):
        # The recovery path: the account page's Add a device mints a FRESH
        # ticket under the existing account (bearer token, no code) — the
        # burned invite code is not needed again.
        status, page = self._signup_and_add_device()
        self.assertEqual(status, 200)
        self.assertIn("expires before you join", page)
        self.assertIn("Add a device", page)
        self.assertIn("not needed again", page)

    def test_the_unconfigured_pages_keep_the_upstream_install_and_repo(self):
        # Backward compatibility: an operator who sets nothing gets exactly
        # the install source and repo link the desk always served.
        status, page = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("https://raw.githubusercontent.com/KidIkaros/vallum/main/scripts/install.sh", page)
        self.assertIn('href="https://github.com/KidIkaros/vallum"', page)
        self.assertIn("github.com/KidIkaros/vallum</a>", page)
        status, page = self.post("/signup", "code=friend-code-1",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertIn("https://raw.githubusercontent.com/KidIkaros/vallum/main/scripts/install.sh", page)
        self.assertIn('href="https://github.com/KidIkaros/vallum"', page)

    def test_the_error_page_carries_the_default_brand(self):
        status, page = self.post("/signup", "",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 403)
        self.assertIn("vallum desk", page)

    def test_the_account_page_shows_the_number_once(self):
        # The account number is the only credential; the page says it is
        # shown once and must be saved — the same contract the ticket page
        # always had, now centred on the durable account.
        status, page = self.post("/signup", "code=friend-code-1",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        # The column holds a digest now — the page is the only place the
        # number ever exists in plaintext, so read it back from there.
        token = re.search(r"[0-9a-f]{32}", page).group()
        self.assertIn("Shown once", page)
        self.assertIn(token, page)
        self.assertIn("Add a device", page)  # the next step is named
        self.assertEqual(self.desk.status(token)[0], 200)

    def test_the_account_page_renders_the_codes_plan_label(self):
        # A code carrying plan "plus" lands a plus account; the page said
        # "trial until" regardless — a false sentence about the plan row.
        status, body = self.post(
            "/api/admin/code",
            json.dumps({"admin_token": "admin-secret", "days": 30, "plan": "plus"}),
            "application/json")
        self.assertEqual(status, 200)
        code = json.loads(body)["code"]
        status, page = self.post("/signup", f"code={code}",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertIn("plus until", page)
        self.assertNotIn("trial until", page)


class LivenessTests(DeskTestCase):
    """/api/account answers "is this device working?" as well as "was it
    issued?". `status` is a provisioning fact; a device that never handshaked
    used to render as plain `active`, which is a lie about the only thing the
    user is looking for."""

    def _token(self):
        account, _ = self.account_with_device()
        return account["token"]

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
        device = {"peer": "p", "status": "active"}
        at_boundary = describe_devices([device], {"p": now - SESSION_LIVE_SECONDS}, now)[0]
        past_boundary = describe_devices([device], {"p": now - SESSION_LIVE_SECONDS - 1}, now)[0]
        self.assertEqual(at_boundary["connection"], "live")
        self.assertEqual(past_boundary["connection"], "offline")

    def test_a_device_the_server_has_no_peer_for_is_unredeemed_not_never(self):
        # The normal outcome of a ticket nobody used: invites live 15 minutes
        # (`INVITE_TTL_SECS`), so a user who signs up and wanders off leaves
        # exactly this. It is not "never connected" — connecting is not something
        # this device can do, because the daemon has no peer to connect to.
        # Observed on the reference desk, where all 14 rows were unredeemed
        # tickets from the alpha session of 2026-11-16.
        code, view = self._account({})
        self.assertEqual(code, 200)
        device = view["devices"][0]
        self.assertEqual(device["status"], "active")
        self.assertEqual(device["connection"], "unredeemed")
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


class DaemonOutageTests(DeskTestCase):
    """A daemon that is down degrades the desk; it does not take it down.

    Two false statements were possible here. The account page could fail with a
    500 for a user whose tunnel was fine — the page whose own comment promises it
    survives exactly that — and the quota could read `0.00 GiB`, a confident
    answer to a question the daemon never answered. The third was the sweep:
    letting the counters exception out meant one blink of the daemon deferred
    every expiry with it.
    """

    def _token(self):
        account, _ = self.account_with_device()
        return account["token"]

    def test_the_account_view_keeps_the_page_and_says_usage_unknown(self):
        token = self._token()
        self.desk.daemon = FakeDaemon(refuse_counters=True, refuse_liveness=True)
        code, view = self.desk.account(token)
        self.assertEqual(code, 200)
        self.assertIsNone(view["bytes_used"])
        self.assertEqual(view["devices"][0]["connection"], "unknown")

    def test_status_says_usage_unknown_rather_than_zero(self):
        token = self._token()
        self.desk.daemon = FakeDaemon(refuse_counters=True)
        code, payload = self.desk.status(token)
        self.assertEqual(code, 200)
        self.assertIsNone(payload["bytes_used"])

    def test_the_page_says_usage_unknown_rather_than_a_number(self):
        token = self._token()
        self.desk.daemon = FakeDaemon(refuse_counters=True, refuse_liveness=True)
        _, view = self.desk.account(token)
        page = desk_module.account_page(view, token)
        self.assertIn("usage unknown", page)
        self.assertNotIn("GiB used", page)

    def test_an_unreachable_daemon_does_not_stop_expiry(self):
        # Quota cannot be judged without counters; expiry can, and an account
        # past its date must still be revoked on that pass.
        token = self._token()
        self.desk.db.execute(
            "UPDATE accounts SET expires='2020-01-01' WHERE token=?", (token_digest(token),))
        self.desk.daemon = FakeDaemon(refuse_counters=True)
        actions = self.desk.sweep_once()
        self.assertEqual([a["reason"] for a in actions], ["expired"])
        self.assertIsNone(actions[0]["bytes"])

    def test_an_unreachable_daemon_does_not_revoke_a_healthy_account(self):
        # No counters is not "used 0 bytes" and not "over quota": no judgement
        # is the only safe answer, because a wrong one removes a working peer.
        self.account_with_device()
        self.desk.daemon = FakeDaemon(refuse_counters=True)
        self.assertEqual(self.desk.sweep_once(), [])


class AccountConversionTests(DeskTestCase):
    """The desk's funnel, on the page its user reads.

    The alpha's fourteen tickets and zero handshakes were legible only in
    `vallum_alpha_*` — where an operator looks and a user does not. The account
    page is where the promise was made ("Get my join ticket"), so the
    ticket-to-connected-device comparison belongs beside the device table, and
    it has to keep its denominator visible there too.
    """

    def _page(self, liveness=None, refuse_liveness=False, extra_devices=()):
        account, _ = self.account_with_device()
        token = account["token"]
        for name in extra_devices:
            self.assertEqual(self.desk.add_device({"token": token, "name": name})[0], 200)
        self.desk.daemon = FakeDaemon(liveness=liveness or {},
                                      refuse_liveness=refuse_liveness)
        code, view = self.desk.account(token)
        self.assertEqual(code, 200)
        return view, desk_module.account_page(view, token)

    def test_a_ticket_nobody_used_reads_zero_of_one_not_a_bare_rate(self):
        view, page = self._page()
        self.assertEqual(view["conversion"],
                         {"devices_total": 1, "devices_connected": 0})
        self.assertIn("0 of 1 device has connected (0%)", page)
        # The sentence names the actual fault: the ticket never became a device.
        self.assertIn("nothing has joined with it yet", page)

    def test_a_device_that_joined_counts_as_converted(self):
        view, page = self._page(liveness={"u0001-friend": int(time.time()) - 5})
        self.assertEqual(view["conversion"]["devices_connected"], 1)
        self.assertIn("1 of 1 device has connected (100%)", page)

    def test_a_device_that_connected_and_stopped_still_counts(self):
        # Same rule as `funnel()`: the join path ran end to end, which is the
        # question. Counting only `live` would report 0% the moment a user
        # closed a laptop.
        _, page = self._page(liveness={"u0001-friend": int(time.time()) - 10_000})
        self.assertIn("not connected", page)
        self.assertIn("1 of 1 device has connected (100%)", page)

    def test_the_rate_travels_with_its_denominator(self):
        _, page = self._page(liveness={"u0001-friend": int(time.time()) - 5},
                             extra_devices=("laptop",))
        self.assertIn("1 of 2 devices have connected (50%)", page)

    def test_an_unreachable_daemon_says_unknown_rather_than_zero(self):
        # A 0% here would be a claim about the join that the desk cannot make.
        view, page = self._page(refuse_liveness=True)
        self.assertIsNone(view["conversion"]["devices_connected"])
        self.assertIn("connected: unknown — the server could not be asked", page)
        self.assertNotIn("0%", page)


class HealthTests(HttpTests):
    """`GET /healthz`: the one route a front or a probe can ask.

    A port that accepts connections proves the process is listening, never that
    it can serve: the database can be gone and the daemon stopped, and both left
    a `200` on `/` promising a ticket the desk would then fail to mint.
    """

    def health(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/healthz")
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read().decode())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read().decode())

    def test_a_working_desk_answers_200_with_each_dependency(self):
        status, body = self.health()
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["checks"]["database"], "ok")
        self.assertEqual(body["checks"]["daemon"], "ok")
        # enrolment is informational (ADR-0034 started-not-armed): present, but
        # never a health gate — a working desk is 200 even when it is inactive.
        self.assertIn("enrolment", body["checks"])

    def test_a_daemon_that_cannot_be_asked_is_a_503_that_names_it(self):
        self.desk.daemon = FakeDaemon(refuse_liveness=True)
        status, body = self.health()
        self.assertEqual(status, 503)
        self.assertFalse(body["ok"])
        self.assertEqual(body["checks"]["daemon"], "unreachable")
        self.assertEqual(body["checks"]["database"], "ok")

    def test_a_database_that_cannot_be_read_is_a_503(self):
        self.desk.db.close()
        status, body = self.health()
        self.assertEqual(status, 503)
        self.assertFalse(body["ok"])
        self.assertIn("unusable", body["checks"]["database"])

    def test_health_carries_no_credential_and_is_not_cached(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/healthz")
        with urllib.request.urlopen(req, timeout=5) as response:
            headers = dict(response.headers)
            body = response.read().decode()
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertNotIn("token", body)
        self.assertNotIn("u0001", body)


class FunnelTests(DeskTestCase):
    """The alpha's one number: tickets minted versus devices that connected.

    Fourteen tickets and zero handshakes read as a healthy quiet system for a
    day, because nothing compared the two. These tests pin the comparison and,
    just as importantly, pin that every series is emitted even when it is zero —
    a metric that vanishes at zero makes "no devices" look like "no desk".
    """

    def _funnel(self, liveness_mapping):
        # Sign up and enrol a device first: an empty desk reports zeros, which
        # would pass several of these assertions for the wrong reason.
        self.account_with_device()
        self.desk.daemon = FakeDaemon(liveness=liveness_mapping)
        return self.desk.funnel()

    def test_a_ticket_nobody_redeemed_counts_as_unredeemed_not_handshaked(self):
        funnel = self._funnel({})
        self.assertEqual(funnel["devices"]["unredeemed"], 1)
        self.assertEqual(funnel["handshaked"], 0)
        self.assertEqual(funnel["devices_total"], 1)

    def test_a_device_that_connected_counts_as_handshaked(self):
        funnel = self._funnel({"u0001-friend": int(time.time()) - 5})
        self.assertEqual(funnel["devices"]["live"], 1)
        self.assertEqual(funnel["handshaked"], 1)

    def test_a_device_that_connected_and_stopped_still_counts_as_handshaked(self):
        # `offline` proves the join path ran end to end, which is the question an
        # alpha asks. Counting only `live` would make the funnel report 0 the
        # moment a user closed their laptop — the opposite of the signal.
        funnel = self._funnel({"u0001-friend": int(time.time()) - 10_000})
        self.assertEqual(funnel["devices"]["offline"], 1)
        self.assertEqual(funnel["handshaked"], 1)

    def test_a_revoked_device_is_not_counted_at_all(self):
        self.account_with_device()
        self.desk.db.execute("UPDATE peers SET status='removed' WHERE peer='u0001-friend'")
        self.desk.daemon = FakeDaemon(liveness={})
        self.assertEqual(self.desk.funnel()["devices_total"], 0)

    def test_a_daemon_that_cannot_answer_is_visible_as_such(self):
        self.account_with_device()
        self.desk.daemon = FakeDaemon(refuse_liveness=True)
        funnel = self.desk.funnel()
        self.assertFalse(funnel["daemon_answered"])
        self.assertEqual(funnel["devices"]["unknown"], 1)

    def test_every_series_is_emitted_even_at_zero(self):
        # The reason the exposition always prints all five states: a series that
        # appears only when nonzero makes an empty alpha indistinguishable from a
        # broken scrape.
        text = desk_module.funnel_exposition(self._funnel({}))
        for state in ("live", "offline", "never", "unredeemed", "unknown"):
            self.assertIn(f'vallum_alpha_devices{{state="{state}"}}', text)
        self.assertIn("vallum_alpha_handshaked_devices 0", text)
        self.assertIn("vallum_alpha_devices_total 1", text)
        self.assertIn("vallum_alpha_daemon_answered 1", text)

    def test_the_exposition_is_parseable_prometheus(self):
        # Shape, not just substrings: every non-comment line is `name[labels] value`
        # and the value is numeric. A malformed scrape is silently dropped by the
        # import endpoint, which would look exactly like a quiet alpha.
        text = desk_module.funnel_exposition(self._funnel({}))
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            name, _, value = line.rpartition(" ")
            self.assertRegex(name, r"^[a-z_]+(\{[a-z_]+=\"[^\"]*\"\})?$")
            float(value)


class RecoveryCodeTests(DeskTestCase):
    """Ownership proof on recovery (premortem 2026-11-19, mode 7): the account
    number is the only credential and there is no PII, so handing a number to
    whoever claims a label is a social-engineering surface. A recovery code shown
    once at signup, stored hashed, lets the operator verify ownership before
    re-issuing a number — without needing the (lost) number itself."""

    def test_signup_returns_a_recovery_code_distinct_from_the_token(self):
        _, account = self.desk.signup({"code": "friend-code-1"})
        rc = account.get("recovery_code")
        self.assertIsNotNone(rc)
        self.assertEqual(len(rc), 16)
        self.assertNotEqual(rc, account["token"])

    def test_recovery_code_is_stored_hashed_not_plaintext(self):
        import hashlib
        _, account = self.desk.signup({"code": "friend-code-1"})
        row = self.desk.db.execute("SELECT recovery_code_hash FROM accounts").fetchone()
        self.assertEqual(row["recovery_code_hash"],
                         hashlib.sha256(account["recovery_code"].encode()).hexdigest())
        self.assertNotEqual(row["recovery_code_hash"], account["recovery_code"])

    def test_reset_token_by_recovery_code_proves_ownership(self):
        _, account = self.desk.signup({"code": "friend-code-1"})
        old = account["token"]
        code, payload = self.desk.admin(
            "/api/admin/reset-token",
            {"admin_token": "admin-secret", "recovery_code": account["recovery_code"]})
        self.assertEqual(code, 200)
        self.assertNotEqual(payload["token"], old)
        self.assertEqual(self.desk.status(old)[0], 404)
        self.assertEqual(self.desk.status(payload["token"])[0], 200)

    def test_reset_token_by_wrong_recovery_code_is_refused(self):
        self.desk.signup({"code": "friend-code-1"})
        code, _ = self.desk.admin(
            "/api/admin/reset-token",
            {"admin_token": "admin-secret", "recovery_code": "0" * 16})
        self.assertEqual(code, 404)

    def test_recovery_code_survives_a_restart(self):
        _, account = self.desk.signup({"code": "friend-code-1"})
        reopened = desk_module.Desk(self.desk.config, FakeDaemon())
        code, _ = reopened.admin(
            "/api/admin/reset-token",
            {"admin_token": "admin-secret", "recovery_code": account["recovery_code"]})
        self.assertEqual(code, 200)

    def test_a_legacy_account_without_a_recovery_code_still_resets_by_peer(self):
        _, device = self.account_with_device()
        self.desk.db.execute("UPDATE accounts SET recovery_code_hash=NULL")
        code, _ = self.desk.admin(
            "/api/admin/reset-token",
            {"admin_token": "admin-secret", "peer": device["peer"]})
        self.assertEqual(code, 200)


class ContactChannelTests(unittest.TestCase):
    """The operator-contact channel (validation premortem B1/B2/C3): invite
    requests, feedback and lost-number recovery need a reachable path, not a
    dead-end 'Try again' loop; the shown-once secrets need a durable download."""

    def test_invite_only_index_offers_a_request_channel(self):
        html = desk_module.index_page(False, contact="ops@example.com")
        self.assertIn("Request an invite", html)
        self.assertIn("mailto:ops@example.com", html)

    def test_the_request_mailto_carries_the_intent(self):
        # A bare mailto opens a blank draft — the clicker is left guessing
        # what the mail app opened for. The draft must arrive addressed.
        html = desk_module.index_page(False, contact="ops@example.com")
        self.assertIn("subject=Vallum%20invite%20request", html)
        self.assertIn("body=", html)
        html = desk_module.account_shell_page(contact="ops@example.com")
        self.assertIn("subject=Vallum%20account%20recovery", html)
        self.assertIn("body=Recovery%20code", html)

    def test_open_signup_index_needs_no_invite_request(self):
        html = desk_module.index_page(True, contact="ops@example.com")
        self.assertNotIn("Request an invite", html)

    def test_login_page_offers_lost_number_recovery(self):
        html = desk_module.account_shell_page(contact="ops@example.com")
        self.assertIn("Lost your number?", html)
        self.assertIn("recovery code", html)

    def test_error_page_offers_recovery_not_just_retry(self):
        html = desk_module.error_page("unknown account token", contact="ops@example.com")
        self.assertIn("Lost your number?", html)
        self.assertIn("mailto:ops@example.com", html)

    def test_no_contact_falls_back_to_guidance_not_a_dead_link(self):
        html = desk_module.index_page(False)
        self.assertIn("the operator who issued your invite code", html)
        self.assertNotIn("mailto:", html)

    def test_signup_page_offers_a_durable_download_and_copy(self):
        html = desk_module.account_created_page(
            {"token": "a" * 32, "recovery_code": "b" * 16,
             "expires": "2026-12-03", "plan": "trial", "bytes_cap": 50 * 1024**3})
        self.assertIn("vallum-account.txt", html)
        self.assertIn("data:text/plain", html)
        self.assertEqual(html.count("data-copy="), 2)

    def test_signup_page_offers_the_account_handoff_link(self):
        html = desk_module.account_created_page(
            {"token": "a" * 32, "recovery_code": "b" * 16,
             "expires": "2026-12-03", "plan": "trial", "bytes_cap": 50 * 1024**3},
            desk_origin="https://desk.wingman.gold")
        self.assertIn("open-client", html)
        self.assertIn("vallum://account?token=", html)

    def test_the_created_page_says_what_queued_means(self):
        html = desk_module.account_created_page(
            {"token": "a" * 32, "recovery_code": "b" * 16, "status": "pending",
             "expires": "2026-12-03", "plan": "trial", "bytes_cap": 0})
        self.assertIn("queued for space", html)
        self.assertIn("a code activates", html)
        self.assertIn("While you wait", html)

    def test_the_account_page_leads_with_activation_when_queued(self):
        view = {"label": "account-1", "plan": "trial", "status": "pending",
                "expires": "2026-12-03", "bytes_cap": 0, "bytes_used": 0,
                "conversion": desk_module.account_conversion([]), "devices": []}
        html = desk_module.account_page(view, "t" * 32)
        self.assertIn("queued for space", html)
        # the code form is hoisted above the device table for a queued account
        self.assertLess(html.index("account/voucher"), html.index("<h2>Devices"))


class ReturnUsageTests(DeskTestCase):
    """Return-usage (validation premortem B2 / exit bar M5): 'wanted' is measured
    by coming back on distinct days, not a single join."""

    def _id(self, account):
        return self.desk.db.execute(
            "SELECT id FROM accounts WHERE token=?",
            (token_digest(account["token"]),)).fetchone()["id"]

    def test_records_distinct_connection_days(self):
        import datetime as dt
        account, device = self.account_with_device()
        peer = device["peer"]
        day1 = dt.datetime(2026, 11, 16, 10, 0, tzinfo=dt.timezone.utc).timestamp()
        day2 = dt.datetime(2026, 11, 17, 10, 0, tzinfo=dt.timezone.utc).timestamp()
        self.desk.daemon = FakeDaemon(liveness={peer: day1})
        self.assertEqual(self.desk.record_connection_days(), 1)
        self.desk.daemon = FakeDaemon(liveness={peer: day2})
        self.assertEqual(self.desk.record_connection_days(), 1)
        self.assertEqual(self.desk.days_connected(self._id(account)), 2)

    def test_same_day_handshakes_count_once(self):
        import datetime as dt
        account, device = self.account_with_device()
        peer = device["peer"]
        morning = dt.datetime(2026, 11, 16, 8, 0, tzinfo=dt.timezone.utc).timestamp()
        evening = dt.datetime(2026, 11, 16, 20, 0, tzinfo=dt.timezone.utc).timestamp()
        self.desk.daemon = FakeDaemon(liveness={peer: morning})
        self.desk.record_connection_days()
        self.desk.daemon = FakeDaemon(liveness={peer: evening})
        self.desk.record_connection_days()
        self.assertEqual(self.desk.days_connected(self._id(account)), 1)

    def test_status_reports_days_connected(self):
        import datetime as dt
        account, device = self.account_with_device()
        sec = dt.datetime(2026, 11, 16, 10, 0, tzinfo=dt.timezone.utc).timestamp()
        self.desk.daemon = FakeDaemon(liveness={device["peer"]: sec})
        self.desk.record_connection_days()
        code, payload = self.desk.status(account["token"])
        self.assertEqual(code, 200)
        self.assertEqual(payload["days_connected"], 1)

    def test_unreachable_daemon_records_nothing(self):
        account, _ = self.account_with_device()
        self.desk.daemon = FakeDaemon(refuse_liveness=True)
        self.assertEqual(self.desk.record_connection_days(), 0)
        self.assertEqual(self.desk.days_connected(self._id(account)), 0)


class FunnelStepTests(DeskTestCase):
    """Per-step journey counters (premortem 2026-11-19, mode 5): the funnel must
    show WHERE conversion drops, not just the terminal state. A stranger who dies
    at install never adds a device, so devices_total stays 0 and the
    ticket-vs-handshake alert cannot fire — the signup/add_device attempt and
    refusal counters locate the drop."""

    def test_signup_ok_and_refused_are_counted_by_reason(self):
        self.desk.signup({"code": "friend-code-1"})   # ok
        self.desk.signup({"code": "nope"})             # forbidden: unknown code
        self.desk.signup({"code": "friend-code-1"})    # forbidden: already used
        events = self.desk.funnel()["events"]["signup"]
        self.assertEqual(events["ok"], 1)
        self.assertEqual(events["refused"].get("forbidden"), 2)

    def test_add_device_ok_and_refused_are_counted_by_reason(self):
        _, account = self.desk.signup({"code": "friend-code-1"})
        self.desk.add_device({"token": account["token"], "name": "laptop"})  # ok
        self.desk.add_device({"token": "nope", "name": "phone"})             # unknown
        events = self.desk.funnel()["events"]["add_device"]
        self.assertEqual(events["ok"], 1)
        self.assertEqual(events["refused"].get("unknown"), 1)

    def test_device_cap_refusal_is_counted_as_limited(self):
        self.desk.config.device_cap = 1
        _, account = self.desk.signup({"code": "friend-code-1"})
        self.desk.add_device({"token": account["token"], "name": "laptop"})  # ok
        code, _ = self.desk.add_device({"token": account["token"], "name": "phone"})
        self.assertEqual(code, 429)
        events = self.desk.funnel()["events"]["add_device"]
        self.assertEqual(events["refused"].get("limited"), 1)

    def test_step_counters_are_emitted_even_at_zero(self):
        text = desk_module.funnel_exposition(self.desk.funnel())
        self.assertIn("vallum_alpha_signup_total 0", text)
        self.assertIn("vallum_alpha_add_device_total 0", text)
        for reason in ("bad_request", "forbidden", "unknown", "conflict",
                       "limited", "daemon", "capacity"):
            self.assertIn(f'vallum_alpha_signup_refused_total{{reason="{reason}"}} 0', text)
            self.assertIn(f'vallum_alpha_add_device_refused_total{{reason="{reason}"}} 0', text)

    def test_step_counters_survive_a_restart(self):
        self.desk.signup({"code": "friend-code-1"})
        self.desk.signup({"code": "nope"})
        reopened = desk_module.Desk(self.desk.config, FakeDaemon())
        events = reopened.funnel()["events"]["signup"]
        self.assertEqual(events["ok"], 1)
        self.assertEqual(events["refused"].get("forbidden"), 1)


class SignupAttributionTests(DeskTestCase):
    """Where a signup came from, and a limit that survives a restart.

    Both exist because an entire alpha session — fourteen accounts from one
    laptop — went unnoticed: nothing recorded an address, so the rows looked like
    fourteen unrelated people, and the only brake on repeat signups lived in
    process memory, so restarting the service reset it.
    """

    def open_desk(self):
        config = dataclasses.replace(self.config, open_signup=True)
        return Desk(config, FakeDaemon())

    def test_a_signup_records_its_address(self):
        desk = self.open_desk()
        self.addCleanup(desk.db.close)
        code, payload = desk.signup({}, client_ip="203.0.113.7")
        self.assertEqual(code, 200)
        row = desk.db.execute(
            "SELECT signup_ip FROM accounts WHERE token=?", (token_digest(payload["token"]),)).fetchone()
        self.assertEqual(row["signup_ip"], "203.0.113.7")

    def test_an_unknown_address_is_recorded_as_absent_not_as_the_string(self):
        # "unknown" is the default argument, not an address. Storing it would put
        # every unattributable signup in one fake bucket and make
        # `shared_ip_accounts` fire on them.
        desk = self.open_desk()
        self.addCleanup(desk.db.close)
        _, payload = desk.signup({})
        row = desk.db.execute(
            "SELECT signup_ip FROM accounts WHERE token=?", (token_digest(payload["token"]),)).fetchone()
        self.assertIsNone(row["signup_ip"])

    def test_the_limit_survives_a_restart(self):
        # The bug this encodes: `signups_today` was a dict on the Desk instance,
        # so `systemctl restart` was a free reset of `--signup-ip-day-limit` on a
        # public desk with open signup.
        first = self.open_desk()
        first.config = dataclasses.replace(first.config, signup_ip_day_limit=2)
        for _ in range(2):
            self.assertEqual(first.signup({}, client_ip="198.51.100.4")[0], 200)
        first.db.close()

        second = self.open_desk()
        self.addCleanup(second.db.close)
        second.config = dataclasses.replace(second.config, signup_ip_day_limit=2)
        code, payload = second.signup({}, client_ip="198.51.100.4")
        self.assertEqual(code, 429, payload)

    def test_a_different_address_gets_its_own_limit(self):
        desk = self.open_desk()
        self.addCleanup(desk.db.close)
        desk.config = dataclasses.replace(desk.config, signup_ip_day_limit=1)
        self.assertEqual(desk.signup({}, client_ip="198.51.100.1")[0], 200)
        self.assertEqual(desk.signup({}, client_ip="198.51.100.1")[0], 429)
        self.assertEqual(desk.signup({}, client_ip="198.51.100.2")[0], 200)

    def test_the_throttle_day_is_utc(self):
        # A desk whose local clock is not UTC would reset the limit early or
        # late; every other timestamp in this service is UTC.
        desk = self.open_desk()
        self.addCleanup(desk.db.close)
        desk._count_signup("203.0.113.9")
        row = desk.db.execute("SELECT day FROM signups WHERE ip='203.0.113.9'").fetchone()
        self.assertEqual(row["day"], datetime.datetime.now(datetime.timezone.utc)
                         .date().isoformat())

    def test_the_funnel_reports_one_machine_many_accounts(self):
        # The signal that would have shown "fourteen accounts, one laptop".
        desk = self.open_desk()
        self.addCleanup(desk.db.close)
        for _ in range(3):
            desk.signup({}, client_ip="203.0.113.50")
        attribution = desk.funnel()["attribution"]
        self.assertEqual(attribution["distinct_ips"], 1)
        self.assertEqual(attribution["shared_ip_accounts"], 3)
        self.assertEqual(attribution["unattributed"], 0)

    def test_accounts_with_no_address_are_counted_not_hidden(self):
        desk = self.open_desk()
        self.addCleanup(desk.db.close)
        desk.signup({})
        desk.signup({}, client_ip="203.0.113.60")
        attribution = desk.funnel()["attribution"]
        self.assertEqual(attribution["unattributed"], 1)
        self.assertEqual(attribution["distinct_ips"], 1)


class DeviceVocabularyTests(unittest.TestCase):
    """The six-state vocabulary lives in one place, and this pins that.

    The bug this prevents: `account()` decided a device's state and the page
    separately decided what that state meant, so adding one state meant editing
    two functions — and the intermediate version told users "never connected"
    about devices that were in fact unredeemed. One function now owns both halves,
    so the only way to add a state is to add it here, where these tests see it.
    """

    def test_every_state_has_a_sentence(self):
        # A state with no sentence would KeyError at page render — i.e. a 500 on
        # the account page for one unlucky user, which is worse than a wrong word.
        for state in DEVICE_STATES:
            described = describe_devices(
                [{"peer": "p", "status": "active"}], self.seen_for(state), 1_000_000)[0]
            self.assertEqual(described["connection"], state)
            self.assertTrue(described["connection_sentence"])

    def test_the_vocabulary_and_the_sentences_cannot_drift(self):
        # Both directions: no state without a sentence, no sentence without a
        # state. This is the assertion that makes the single-definition claim real
        # rather than a comment.
        sentences = desk_module._SENTENCE
        self.assertEqual(set(sentences) - {None}, set(DEVICE_STATES))

    def test_no_two_states_share_a_sentence(self):
        # Each state sends the reader to a different fix, so two states reading
        # the same is a sign one of them is redundant.
        said = [sentences(0) for state, sentences in desk_module._SENTENCE.items()
                if state is not None]
        self.assertEqual(len(said), len(set(said)), said)

    def test_every_state_is_reachable_from_real_inputs(self):
        # Not just "the map has entries": each state must be producible by an
        # input the daemon can actually give. A state nothing can produce is
        # dead vocabulary that still has to be maintained.
        now = 1_000_000
        cases = {
            "live": ({"peer": "p", "status": "active"}, {"p": now - 10}),
            "offline": ({"peer": "p", "status": "active"}, {"p": now - 10_000}),
            "never": ({"peer": "p", "status": "active"}, {"p": None}),
            "unredeemed": ({"peer": "p", "status": "active"}, {}),
            "unknown": ({"peer": "p", "status": "active"}, None),
        }
        self.assertEqual(set(cases), set(DEVICE_STATES))
        for expected, (device, seen) in cases.items():
            self.assertEqual(
                describe_devices([device], seen, now)[0]["connection"], expected)

    def test_a_revoked_device_has_no_state_at_all(self):
        # `None`, not a word: there is no peer left to ask about, so any word
        # would be a claim about something that does not exist.
        described = describe_devices(
            [{"peer": "p", "status": "removed"}], {"p": 1}, 1_000_000)[0]
        self.assertIsNone(described["connection"])
        self.assertEqual(described["connection_sentence"], "—")

    def seen_for(self, state):
        now = 1_000_000
        return {
            "live": {"p": now - 10},
            "offline": {"p": now - 10_000},
            "never": {"p": None},
            "unredeemed": {},
            "unknown": None,
        }[state]

    def test_describe_does_not_mutate_its_input(self):
        # It returns new dicts, so a caller that ignores the result cannot
        # half-apply it and leave a device with a state but no sentence.
        device = {"peer": "p", "status": "active"}
        describe_devices([device], {"p": None}, 1_000_000)
        self.assertEqual(device, {"peer": "p", "status": "active"})


class AccountPageTests(HttpTests):
    """The account surface: the bearer token travels POST bodies only —
    never the request line — and every rendered page is private."""

    def _token(self):
        status, body = self.post("/api/signup", "{}", "application/json")
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
        self.desk.add_device({"token": token, "name": "friend"})
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
        self.desk.add_device({"token": token, "name": "friend"})
        status, body = self.post("/api/status", json.dumps({"token": token}),
                                 "application/json")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["peer"], "u0001-friend")

    def test_the_account_page_is_private_and_noindexed(self):
        token = self._token()
        self.desk.add_device({"token": token, "name": "friend"})
        status, headers, page = self.post_headers(
            "/account", f"token={token}", "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(headers.get("X-Robots-Tag"), "noindex")
        self.assertIn("u0001-friend", page)

    def test_the_account_created_page_is_private_and_noindexed(self):
        # The signup answer carries the only credential — it must not be
        # cached or crawled, exactly like every other credential-bearing page.
        status, headers, page = self.post_headers(
            "/signup", "", "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(headers.get("X-Robots-Tag"), "noindex")

    def test_the_account_shell_needs_no_script(self):
        status, _, page = self.get("/account")
        self.assertEqual(status, 200)
        self.assertNotIn("<script", page)
        self.assertIn('name="token"', page)

    def test_the_account_page_escapes_the_label(self):
        token = self._token()
        self.desk.db.execute(
            "UPDATE accounts SET label='<img onerror=x>' WHERE token=?", (token_digest(token),))
        _, _, page = self.post_headers(
            "/account", f"token={token}", "application/x-www-form-urlencoded")
        self.assertNotIn("<img", page)
        self.assertIn("&lt;img", page)

    def test_the_page_revokes_only_the_accounts_own_device(self):
        token = self._token()
        self.desk.add_device({"token": token, "name": "friend"})
        self.desk.add_device({"token": token, "name": "laptop"})
        status, _, _ = self.post_headers(
            "/account/revoke", f"token={token}&peer=u0002-laptop&confirm=yes",
            "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertEqual(self.daemon.removed, ["u0002-laptop"])
        # Another account's peer is not ours to remove.
        other_token = self._token()
        _, other_device = self.desk.add_device({"token": other_token, "name": "other"})
        other_peer = other_device["peer"]
        status, _, _ = self.post_headers(
            "/account/revoke", f"token={token}&peer={other_peer}&confirm=yes",
            "application/x-www-form-urlencoded")
        self.assertEqual(status, 404)
        self.assertNotIn(other_peer, self.daemon.removed)

    def test_a_bare_revoke_click_confirms_before_it_acts(self):
        # The only destructive self-service action needs a forcing function:
        # the first click answers a page naming what removal costs, and the
        # peer is untouched until `confirm=yes` arrives.
        token = self._token()
        self.desk.add_device({"token": token, "name": "laptop"})
        status, _, page = self.post_headers(
            "/account/revoke", f"token={token}&peer=u0001-laptop",
            "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertIn("Remove laptop?", page)
        self.assertIn('name="confirm" value="yes"', page)
        self.assertEqual(self.daemon.removed, [])
        status, _, page = self.post_headers(
            "/account/revoke", f"token={token}&peer=u0001-laptop&confirm=yes",
            "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertEqual(self.daemon.removed, ["u0001-laptop"])
        self.assertIn("removed u0001-laptop", page)

    def test_the_ticket_page_emits_the_deep_link_and_the_number(self):
        token = self._token()
        status, page = self.post("/account/device", f"token={token}&name=form-user",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        from urllib.parse import quote
        expected = (f"vallum://join?ticket={quote('vallum1-join:203.0.113.9:51922/u0001-form-use/deadbeef/token/fingerprint', safe='')}"
                    f"&amp;account={token}")
        self.assertIn(expected, page)
        # The URI is fired by script — the token must never sit in an href
        # or another attribute a prefetcher or Referer header would carry.
        import re
        for href in re.findall(r'href="([^"]*)"', page):
            self.assertNotIn(token, href)

    def test_the_ticket_page_names_the_account_number(self):
        token = self._token()
        status, page = self.post("/account/device", f"token={token}&name=form-user",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertIn("account number", page)
        self.assertIn(token, page)

    def test_the_signup_json_carries_no_ticket(self):
        # ADR-0047: the account is created alone; the ticket belongs to the
        # device enrolment. A signup answer carrying a ticket would mean the
        # old conflation had crept back in.
        status, body = self.post("/api/signup", "{}", "application/json")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertNotIn("ticket", payload)
        self.assertNotIn("connect", payload)
        self.assertTrue(payload["token"])

    def test_the_devices_json_carries_the_deep_link(self):
        token = self._token()
        status, body = self.post("/api/devices",
                                 json.dumps({"token": token, "name": "json-user"}),
                                 "application/json")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["connect"].startswith("vallum://join?ticket="))
        self.assertIn(f"&account={token}", payload["connect"])

    def test_the_add_device_form_mints_a_bound_ticket(self):
        token = self._token()
        status, _, page = self.post_headers(
            "/account/device", f"token={token}&name=laptop",
            "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertIn("vallum1-join:", page)

    def test_the_add_device_ticket_carries_the_desk_origin(self):
        # The expired-ticket recovery path ends here: the fresh ticket's
        # connect URI must carry the desk origin too, or the recovered device
        # never learns where its account lives (ADR-0046).
        from urllib.parse import quote
        token = self._token()
        status, _, page = self.post_headers(
            "/account/device", f"token={token}&name=laptop",
            "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        origin = f"https://127.0.0.1:{self.port}"
        self.assertIn(f"&amp;desk={quote(origin, safe='')}", page)

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
        # v0 → v2 in one start: every step runs in order, so a database from the
        # alpha desk lands on the current version without an intermediate stop.
        self.assertEqual(version, desk_module.SCHEMA_VERSION)
        rows = desk.db.execute("SELECT peer, status FROM peers ORDER BY peer").fetchall()
        self.assertEqual([r["peer"] for r in rows], ["u0001-old", "u0002-old"])
        # The legacy column stays populated — the expand step keeps old
        # readers working while the contract is still ahead of us.
        accounts = desk.db.execute("SELECT peer FROM accounts ORDER BY peer").fetchall()
        self.assertEqual([a["peer"] for a in accounts], ["u0001-old", "u0002-old"])
        columns = {r[1] for r in desk.db.execute("PRAGMA table_info(codes)")}
        self.assertTrue({"days", "bytes", "plan"} <= columns)

    def test_a_v1_database_gains_the_signup_address_column(self):
        # The fourteen accounts from 2026-11-16 predate address recording, so
        # they migrate to `signup_ip = NULL`. That is the honest answer — their
        # addresses were never captured — and the funnel reports the count of
        # unattributed rows rather than pretending they were attributed.
        path = os.path.join(self.tempdir.name, "v1.sqlite")
        conn = sqlite3.connect(path)
        conn.executescript(desk_module.SCHEMA)
        conn.execute("PRAGMA user_version=1")
        conn.execute(
            "INSERT INTO accounts (peer,label,token,code,created,expires,bytes_cap,status) "
            "VALUES ('u0001-old','old','tok','legacy','2026-11-16','2027-01-01',1000,'active')")
        conn.commit()
        conn.close()

        config = dataclasses.replace(self.config, state=path)
        desk = Desk(config, self.daemon)
        self.addCleanup(desk.db.close)
        self.assertEqual(
            desk.db.execute("PRAGMA user_version").fetchone()[0], desk_module.SCHEMA_VERSION)
        row = desk.db.execute("SELECT signup_ip FROM accounts WHERE peer='u0001-old'").fetchone()
        self.assertIsNone(row["signup_ip"])
        self.assertEqual(desk.funnel()["attribution"]["unattributed"], 1)

    def test_a_database_newer_than_this_build_is_refused(self):
        path = os.path.join(self.tempdir.name, "newer.sqlite")
        conn = sqlite3.connect(path)
        conn.executescript(desk_module.SCHEMA)
        conn.execute("PRAGMA user_version=99")
        conn.close()
        config = dataclasses.replace(self.config, state=path)
        with self.assertRaises(RuntimeError):
            Desk(config, self.daemon)

    def v2_db(self):
        """A v2 database the way the desk wrote it before ADR-0047: every
        account carried its first device in a NOT NULL `peer` column. The
        DDL is hardcoded here on purpose — it is the *old* shape, and must
        not drift when `desk_module.SCHEMA` moves on."""
        path = os.path.join(self.tempdir.name, "v2.sqlite")
        conn = sqlite3.connect(path)
        conn.executescript("""
            CREATE TABLE accounts (
                id INTEGER PRIMARY KEY, peer TEXT UNIQUE NOT NULL,
                label TEXT NOT NULL, token TEXT UNIQUE NOT NULL,
                code TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'trial',
                created TEXT NOT NULL, expires TEXT NOT NULL,
                bytes_cap INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'active', paid_until TEXT,
                signup_ip TEXT);
            CREATE TABLE peers (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id),
                peer TEXT UNIQUE NOT NULL, label TEXT NOT NULL,
                created TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active');
            CREATE TABLE signups (ip TEXT NOT NULL, day TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (ip, day));
            CREATE TABLE codes (code TEXT PRIMARY KEY, created TEXT NOT NULL,
                used_by TEXT, days INTEGER, bytes INTEGER, plan TEXT);
            INSERT INTO accounts (peer,label,token,code,created,expires,bytes_cap,status)
                VALUES ('u0001-old','old-friend','tok-v2','legacy','2026-11-01',
                        '2027-01-01',1000,'active');
            INSERT INTO peers (account_id,peer,label,created,status)
                VALUES (1,'u0001-old','old-friend','2026-11-01','active');
        """)
        conn.execute("PRAGMA user_version=2")
        conn.close()
        return path

    def test_a_v2_database_migrates_to_a_nullable_peer(self):
        # ADR-0047: the account is not the device. An account-only signup
        # writes peer=NULL, which the old NOT NULL column refuses — so the
        # table is rebuilt, keeping every row. SQLite cannot drop NOT NULL
        # in place; the migration must copy, not ALTER.
        config = dataclasses.replace(self.config, state=self.v2_db())
        desk = Desk(config, self.daemon)
        self.addCleanup(desk.db.close)
        self.assertEqual(
            desk.db.execute("PRAGMA user_version").fetchone()[0],
            desk_module.SCHEMA_VERSION)
        peer_column = [r for r in desk.db.execute("PRAGMA table_info(accounts)")
                       if r[1] == "peer"][0]
        self.assertEqual(peer_column[3], 0, "accounts.peer must accept NULL")
        row = desk.db.execute("SELECT * FROM accounts WHERE token=?",
                              (token_digest("tok-v2"),)).fetchone()
        self.assertEqual(row["peer"], "u0001-old")
        self.assertEqual(row["label"], "old-friend")
        self.assertEqual(
            desk.db.execute("SELECT peer FROM peers").fetchone()["peer"], "u0001-old")
        # The rebuilt column accepts the new shape: an account with no device.
        desk.db.execute(
            "INSERT INTO accounts (peer,label,token,code,created,expires,bytes_cap,status) "
            "VALUES (NULL,'account-2','tok-new','open','2026-11-19','2027-01-01',1000,'active')")
        self.assertIsNone(desk.db.execute(
            "SELECT peer FROM accounts WHERE token='tok-new'").fetchone()["peer"])

    def test_a_legacy_account_keeps_its_device_after_migration(self):
        # The cohort's existing accounts must keep working: the device the
        # legacy column names is still reported, still enforced, still
        # revocable — migration changes the shape, never the facts.
        config = dataclasses.replace(self.config, state=self.legacy_db())
        desk = Desk(config, self.daemon)
        self.addCleanup(desk.db.close)
        code, view = desk.account("tok-1")
        self.assertEqual(code, 200)
        self.assertEqual([d["peer"] for d in view["devices"]], ["u0001-old"])
        code, status = desk.status("tok-1")
        self.assertEqual(code, 200)
        self.assertEqual(status["peers"], ["u0001-old"])
        desk.db.execute("UPDATE accounts SET expires='2020-01-01' WHERE token=?",
                        (token_digest("tok-1"),))
        actions = desk.sweep_once()
        # tok-2 is already expired in the fixture, so its peer is swept as an
        # orphan on the same pass — assert our account's fact, not the total.
        self.assertIn("expired", [a["reason"] for a in actions])
        self.assertIn("u0001-old", self.daemon.removed)

    def test_migration_is_idempotent(self):
        # A desk restarts often (peer invite restarts the daemon beside it);
        # opening an already-migrated file must not rebuild or duplicate.
        config = dataclasses.replace(self.config, state=self.v2_db())
        first = Desk(config, self.daemon)
        first.db.close()
        second = Desk(config, self.daemon)
        self.addCleanup(second.db.close)
        self.assertEqual(
            second.db.execute("PRAGMA user_version").fetchone()[0],
            desk_module.SCHEMA_VERSION)
        self.assertEqual(
            second.db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0], 1)
        self.assertEqual(
            second.db.execute("SELECT COUNT(*) FROM peers").fetchone()[0], 1)

    def test_an_interrupted_rebuild_recovers_on_the_next_start(self):
        # A crash mid-rebuild can leave the scratch table (accounts_v3)
        # behind. The next start must clear it and finish the migration —
        # not wedge on "table already exists", and not silently rebuild over
        # an empty accounts table.
        path = self.v2_db()
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE accounts_v3 (id INTEGER PRIMARY KEY)")
        conn.close()
        config = dataclasses.replace(self.config, state=path)
        desk = Desk(config, self.daemon)
        self.addCleanup(desk.db.close)
        self.assertEqual(
            desk.db.execute("PRAGMA user_version").fetchone()[0],
            desk_module.SCHEMA_VERSION)
        self.assertEqual(
            desk.db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0], 1)
        self.assertEqual(
            desk.db.execute("SELECT peer FROM accounts").fetchone()["peer"], "u0001-old")
        self.assertIsNone(desk.db.execute(
            "SELECT name FROM sqlite_master WHERE name='accounts_v3'").fetchone())


class PeersRelationTests(DeskTestCase):
    """Every reader consults the peers relation, not the legacy column."""

    def test_signup_writes_no_peer_row(self):
        # ADR-0047: the account is created alone. No peers row, no legacy
        # column value — the device arrives later, through add_device.
        self.signup()
        account = self.desk.db.execute("SELECT * FROM accounts").fetchone()
        self.assertIsNone(account["peer"])
        self.assertIsNone(self.desk.db.execute(
            "SELECT * FROM peers WHERE account_id=?", (account["id"],)).fetchone())

    def test_add_device_writes_the_peer_row(self):
        account, device = self.account_with_device()
        account_id = self.desk.db.execute(
            "SELECT id FROM accounts WHERE token=?", (token_digest(account["token"]),)).fetchone()["id"]
        row = self.desk.db.execute(
            "SELECT * FROM peers WHERE account_id=?", (account_id,)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["peer"], device["peer"])
        self.assertEqual(row["status"], "active")
        # The legacy column stays NULL for new accounts: the relation is the
        # truth, and the column is kept only for pre-migration/adopted rows.
        self.assertIsNone(self.desk.db.execute(
            "SELECT peer FROM accounts WHERE id=?", (account_id,)).fetchone()["peer"])

    def test_the_relation_falls_back_to_the_legacy_column(self):
        # A pre-migration row: the device lives in the account's own column
        # with no peers row. Readers must still find it.
        account, device = self.account_with_device()
        account_id = self.desk.db.execute(
            "SELECT id FROM accounts WHERE token=?", (token_digest(account["token"]),)).fetchone()["id"]
        self.desk.db.execute("DELETE FROM peers")
        self.desk.db.execute("UPDATE accounts SET peer=? WHERE id=?",
                             (device["peer"], account_id))
        code, status = self.desk.status(account["token"])
        self.assertEqual(code, 200)
        self.assertEqual(status["peer"], device["peer"])

    def test_adopting_writes_the_peers_row(self):
        self.desk.admin("/api/admin/adopt",
                        {"admin_token": "admin-secret", "peer": "existing-peer"})
        row = self.desk.db.execute(
            "SELECT * FROM peers WHERE peer='existing-peer'").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "active")

    def test_revoking_marks_the_peers_row_removed(self):
        account, device = self.account_with_device()
        self.desk.db.execute(
            "UPDATE accounts SET expires='2020-01-01' WHERE token=?", (token_digest(account["token"]),))
        self.desk.sweep_once()
        row = self.desk.db.execute(
            "SELECT status FROM peers WHERE peer=?", (device["peer"],)).fetchone()
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
        status, payload = self.signup(code=minted["code"])
        self.assertEqual(status, 200)
        row = self.desk.db.execute(
            "SELECT * FROM accounts WHERE token=?", (token_digest(payload["token"]),)).fetchone()
        self.assertEqual(row["plan"], "plus")
        self.assertEqual(row["bytes_cap"], 5000)
        expected = (datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(days=30)).date().isoformat()
        self.assertEqual(row["expires"], expected)

    def test_a_payload_less_code_still_lands_the_trial(self):
        _, minted = self.desk._mint_code({})
        status, payload = self.signup(code=minted["code"])
        self.assertEqual(status, 200)
        row = self.desk.db.execute(
            "SELECT * FROM accounts WHERE token=?", (token_digest(payload["token"]),)).fetchone()
        self.assertEqual(row["plan"], "trial")
        self.assertEqual(row["bytes_cap"], 1000)

    def test_a_code_redeems_once_even_under_a_race(self):
        _, minted = self.desk._mint_code({})
        results = []
        threads = [threading.Thread(
            target=lambda: results.append(
                self.desk.signup({"code": minted["code"]})[0]))
            for _ in range(2)]
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
    and revocation splits into per-device and per-account. The account is
    created alone (ADR-0047); every device here arrives through add_device."""

    def _token(self):
        _, payload = self.signup()
        return payload["token"]

    def test_an_account_adds_a_device_and_gets_a_ticket(self):
        token = self._token()
        code, payload = self.desk.add_device({"token": token, "name": "laptop"})
        self.assertEqual(code, 200)
        self.assertTrue(payload["ticket"].startswith("vallum1-join:"))
        self.assertEqual(payload["peer"], "u0001-laptop")
        rows = self.desk.db.execute(
            "SELECT peer FROM peers WHERE status='active' ORDER BY peer").fetchall()
        self.assertEqual([r["peer"] for r in rows], ["u0001-laptop"])

    def test_a_device_with_a_public_key_gets_a_pinned_invite(self):
        # ADR-0047 §3: the client keygens locally and presents its public
        # line; the desk mints an invite bound to that key, so a stolen
        # account token enrols nothing without the matching private key.
        token = self._token()
        line = "vallum1:0003:" + "ab" * 32 + ":-"
        code, payload = self.desk.add_device(
            {"token": token, "name": "laptop", "public_key": line})
        self.assertEqual(code, 200)
        self.assertIs(payload["pinned"], True)
        self.assertEqual(self.daemon.pins[payload["peer"]], line)

    def test_a_device_without_a_public_key_stays_unpinned(self):
        # The web account page's path: no pre-shared line, the client
        # generates its key at join time. Single-use, not pinned — and the
        # response says so, so a caller can tell the two apart.
        token = self._token()
        code, payload = self.desk.add_device({"token": token, "name": "laptop"})
        self.assertEqual(code, 200)
        self.assertIs(payload["pinned"], False)
        self.assertIsNone(self.daemon.pins[payload["peer"]])

    def test_a_malformed_public_key_is_refused_before_any_reservation(self):
        # A bad line is the caller's mistake, not the daemon's: it is a 400
        # that burns no device slot and makes no daemon call. The shapes
        # mirror `keys::decode_public` — the daemon would refuse them too,
        # but only after the reservation existed.
        token = self._token()
        bad_lines = [
            "not-a-line",
            "vallum2:0003:abcd:-",          # wrong tag
            "vallum1:0003:abcd",            # three fields
            "vallum1:0003:abcd:-:extra",    # five fields
            "vallum1:zzzz:abcd:-",          # suite not hex
            "vallum1:0003::-",              # empty KEM
            "vallum1:0003:abcd:",           # empty signing (only `-` means none)
            "vallum1:0003:nothex:-",        # KEM not hex
            "vallum1:0003:abcd:nothex",     # signing not hex
            "vallum1:0003:abc:-",           # odd-length hex
            "vallum1:0003:" + "ab" * 5000 + ":-",  # absurdly long
        ]
        for line in bad_lines:
            with self.subTest(line=line[:40]):
                code, payload = self.desk.add_device(
                    {"token": token, "name": "laptop", "public_key": line})
                self.assertEqual(code, 400)
                self.assertIn("public_key", payload["error"])
        self.assertEqual(self.daemon.minted, [])
        self.assertEqual(
            self.desk.db.execute("SELECT COUNT(*) FROM peers").fetchone()[0], 0)

    def test_a_wrapped_public_key_is_canonicalized_before_pinning(self):
        # The pin is a byte comparison of the whole line at the responder
        # (`decide_invite`), while the client presents the canonical line
        # `vallum pubkey` prints: lowercase hex, four-digit suite, no
        # whitespace. A paste that wrapped in an editor, or uppercase hex,
        # or a short suite field must be normalized to exactly that form —
        # otherwise the invite is minted and then refused at join time.
        token = self._token()
        wrapped = "vallum1:3:ABCD\n  EF01:-"
        code, payload = self.desk.add_device(
            {"token": token, "name": "laptop", "public_key": wrapped})
        self.assertEqual(code, 200)
        self.assertIs(payload["pinned"], True)
        self.assertEqual(self.daemon.pins[payload["peer"]], "vallum1:0003:abcdef01:-")

    def test_a_non_string_public_key_is_a_400_not_a_crash(self):
        # A JSON number or list where a line belongs is the caller's mistake:
        # it must be a 400 naming the field, not an AttributeError behind a
        # 500 — and it burns no slot.
        token = self._token()
        for bad in (123, ["vallum1:0003:abcd:-"], {"line": "x"}, True):
            with self.subTest(bad=bad):
                code, payload = self.desk.add_device(
                    {"token": token, "name": "laptop", "public_key": bad})
                self.assertEqual(code, 400)
                self.assertIn("public_key", payload["error"])
        self.assertEqual(self.daemon.minted, [])
        self.assertEqual(
            self.desk.db.execute("SELECT COUNT(*) FROM peers").fetchone()[0], 0)

    def test_a_failed_pinned_mint_leaves_a_tombstone(self):
        # A daemon refusal marks the reservation removed rather than deleting
        # it: the slot frees, the name is never reissued, and the audit trail
        # keeps the attempt — the same treatment a ghost reservation gets.
        token = self._token()
        self.daemon._refuse = True
        code, payload = self.desk.add_device(
            {"token": token, "name": "laptop",
             "public_key": "vallum1:0003:" + "ab" * 32 + ":-"})
        self.assertEqual(code, 502)
        self.assertIn("daemon refused", payload["error"])
        rows = self.desk.db.execute("SELECT status FROM peers").fetchall()
        self.assertEqual([r["status"] for r in rows], ["removed"])

    def test_an_empty_public_key_is_the_unpinned_path(self):
        # A form or UTCP template that always sends the field sends it empty
        # when the caller has no line: that is absence, not a malformed pin.
        token = self._token()
        for empty in ("", "   "):
            code, payload = self.desk.add_device(
                {"token": token, "name": "laptop", "public_key": empty})
            self.assertEqual(code, 200)
            self.assertIs(payload["pinned"], False)

    def test_peer_names_differ_in_their_first_eight_characters(self):
        # The kernel's interface-name ceiling truncates at fifteen characters,
        # so two peers sharing a prefix would collide on one machine.
        first = self._token()
        _, alpha = self.desk.add_device({"token": first, "name": "alpha"})
        second = self.desk.signup({"code": "friend-code-2"})[1]["token"]
        _, beta = self.desk.add_device({"token": second, "name": "beta"})
        self.assertEqual(alpha["peer"], "u0001-alpha")
        self.assertEqual(beta["peer"], "u0002-beta")

    def test_the_device_ticket_binds_the_accounts_plan(self):
        _, minted = self.desk._mint_code({"days": 30, "bytes": 5000, "plan": "plus"})
        _, signup_payload = self.signup(code=minted["code"])
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
        self.desk.admin("/api/admin/revoke-account",
                        {"admin_token": "admin-secret", "token": token})
        code, payload = self.desk.add_device({"token": token, "name": "laptop"})
        self.assertEqual(code, 403)

    def test_the_device_cap_is_a_ceiling(self):
        self.desk.config.device_cap = 2
        token = self._token()
        self.assertEqual(self.desk.add_device({"token": token, "name": "laptop"})[0], 200)
        self.assertEqual(self.desk.add_device({"token": token, "name": "phone"})[0], 200)
        code, payload = self.desk.add_device({"token": token, "name": "tablet"})
        self.assertEqual(code, 429)
        self.assertIn("device limit", payload["error"])
        self.assertEqual(
            self.desk.db.execute("SELECT COUNT(*) FROM peers").fetchone()[0], 2)

    def test_the_cap_holds_under_a_race(self):
        self.desk.config.device_cap = 1
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
                "SELECT COUNT(*) FROM peers WHERE status='active'").fetchone()[0], 1)

    def test_devices_share_the_account_byte_pool(self):
        token = self._token()
        self.desk.add_device({"token": token, "name": "friend"})
        self.desk.add_device({"token": token, "name": "laptop"})
        self.daemon._counters = {"u0001-friend": 600, "u0002-laptop": 600}
        actions = self.desk.sweep_once()
        self.assertEqual(actions[0]["reason"], "overquota")
        self.assertEqual(sorted(self.daemon.removed), ["u0001-friend", "u0002-laptop"])
        row = self.desk.db.execute("SELECT status FROM accounts").fetchone()
        self.assertEqual(row["status"], "overquota")

    def test_per_device_revoke_keeps_the_account(self):
        token = self._token()
        self.desk.add_device({"token": token, "name": "friend"})
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
        self.desk.add_device({"token": token, "name": "friend"})
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
        self.daemon.missing_peers = ["u0001-laptop"]
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
                "SELECT COUNT(*) FROM peers WHERE status='active'").fetchone()[0], 0)

    def test_removing_a_device_needs_a_peer_name_even_with_devices(self):
        # The ownership check compares against the legacy column, which is
        # NULL for every new-contract account — even one carrying devices.
        token = self._token()
        self.desk.add_device({"token": token, "name": "laptop"})
        code, payload = self.desk.remove_device({"token": token})
        self.assertEqual(code, 400)
        self.assertEqual(self.daemon.removed, [])

    def test_remove_device_refuses_non_string_peer_and_token(self):
        # Same intake rule as rotate: a non-string name is a 400 naming the
        # field, not a bind error behind a 500 (the gap pre-dated rotate).
        token = self._token()
        _, device = self.desk.add_device({"token": token, "name": "laptop"})
        for bad in (["x"], {"p": 1}, 123, True):
            with self.subTest(peer=bad):
                code, payload = self.desk.remove_device({"token": token, "peer": bad})
                self.assertEqual(code, 400)
                self.assertIn("peer", payload["error"])
        for bad in (["tok"], {"t": 1}, 123):
            with self.subTest(token=bad):
                code, payload = self.desk.remove_device(
                    {"token": bad, "peer": device["peer"]})
                self.assertEqual(code, 400)
                self.assertIn("token", payload["error"])
        self.assertEqual(self.daemon.removed, [])


class RotationTests(DeskTestCase):
    """ADR-0047 §4: rotation replaces a device's key under its stable name;
    the slot is preserved. The finalize-in-same-call decision and its
    rationale live in DaemonCli.rotate and the CONTEXT.md glossary."""

    LINE = "vallum1:0003:" + "cd" * 32 + ":-"

    def test_rotation_replaces_the_key_under_the_stable_name(self):
        account, device = self.account_with_device()
        peer = device["peer"]
        code, payload = self.desk.rotate_device(
            {"token": account["token"], "peer": peer, "public_key": self.LINE})
        self.assertEqual(code, 200)
        self.assertEqual(payload["rotated"], peer)
        self.assertTrue(payload["fingerprint"])
        self.assertIs(payload["finalized"], True)
        # The daemon rotated exactly this peer to exactly this line…
        self.assertEqual(self.daemon.rotated, [(peer, self.LINE)])
        # …and nothing was minted, reserved or removed: the slot is the same.
        self.assertEqual(self.daemon.minted, [peer])  # only the enrolment mint
        self.assertEqual(self.daemon.removed, [])
        rows = self.desk.db.execute(
            "SELECT peer, status FROM peers ORDER BY peer").fetchall()
        self.assertEqual([(r["peer"], r["status"]) for r in rows], [(peer, "active")])

    def test_rotation_preserves_the_device_count_at_the_cap(self):
        # The load-bearing acceptance (ADR-0047 §4): a capped account must
        # still be able to rotate — rotation is never add_device, so it
        # neither checks nor burns the cap.
        self.config.device_cap = 1
        account, device = self.account_with_device()
        code, _ = self.desk.rotate_device(
            {"token": account["token"], "peer": device["peer"], "public_key": self.LINE})
        self.assertEqual(code, 200)
        self.assertEqual(
            self.desk.db.execute(
                "SELECT COUNT(*) FROM peers WHERE status='active'").fetchone()[0], 1)
        # The cap itself still bites for a NEW device — unchanged.
        code, _ = self.desk.add_device({"token": account["token"], "name": "second"})
        self.assertEqual(code, 429)

    def test_rotation_requires_a_public_key(self):
        # There is no unpinned rotation: the point is the client's OWN new
        # key (custody, ADR-0013). Server-generation (--ship-key) is an
        # explicit operator opt-in, not this path. Absent/empty is a 400
        # naming the fix, and makes no daemon call.
        account, device = self.account_with_device()
        for missing in ({}, {"public_key": ""}, {"public_key": "   "}):
            with self.subTest(missing=missing):
                body = {"token": account["token"], "peer": device["peer"]}
                body.update(missing)
                code, payload = self.desk.rotate_device(body)
                self.assertEqual(code, 400)
                self.assertIn("public_key", payload["error"])
        self.assertEqual(self.daemon.rotated, [])

    def test_rotation_refuses_a_non_string_public_key(self):
        # Same rule as add_device: a JSON number/list/bool where a line
        # belongs is a 400 naming the field, not an AttributeError behind
        # a 500 — and no daemon call.
        account, device = self.account_with_device()
        for bad in (123, ["vallum1:0003:abcd:-"], {"line": "x"}, True):
            with self.subTest(bad=bad):
                code, payload = self.desk.rotate_device(
                    {"token": account["token"], "peer": device["peer"], "public_key": bad})
                self.assertEqual(code, 400)
                self.assertIn("public_key", payload["error"])
        self.assertEqual(self.daemon.rotated, [])

    def test_rotation_refuses_a_malformed_line_before_any_daemon_call(self):
        account, device = self.account_with_device()
        bad_lines = [
            "not-a-line",
            "vallum2:0003:abcd:-",
            "vallum1:0003:abcd",
            "vallum1:zzzz:abcd:-",
            "vallum1:0003::-",
            "vallum1:0003:abc:-",
        ]
        for line in bad_lines:
            with self.subTest(line=line):
                code, payload = self.desk.rotate_device(
                    {"token": account["token"], "peer": device["peer"], "public_key": line})
                self.assertEqual(code, 400)
                self.assertIn("public_key", payload["error"])
        self.assertEqual(self.daemon.rotated, [])

    def test_rotation_canonicalizes_a_wrapped_public_key(self):
        # Same whole-line discipline as the pin: the daemon stores the line
        # verbatim, so a wrapped/uppercase paste must be normalized to the
        # canonical `vallum pubkey` form before it reaches the config.
        account, device = self.account_with_device()
        code, _ = self.desk.rotate_device(
            {"token": account["token"], "peer": device["peer"],
             "public_key": "vallum1:3:CD\n  EF:-"})
        self.assertEqual(code, 200)
        self.assertEqual(self.daemon.rotated, [(device["peer"], "vallum1:0003:cdef:-")])

    def test_rotation_needs_a_peer_name_even_with_devices(self):
        # The ownership check compares against the legacy column, which is
        # NULL on every new-contract account: `None != None` is False, so a
        # missing peer would slip through and rotate nothing (the slice-a
        # remove_device bug, pinned here for the new verb).
        account, _ = self.account_with_device()
        for missing in ({}, {"peer": None}, {"peer": ""}):
            with self.subTest(missing=missing):
                body = {"token": account["token"], "public_key": self.LINE}
                body.update(missing)
                code, payload = self.desk.rotate_device(body)
                self.assertEqual(code, 400)
                self.assertIn("peer", payload["error"])
        self.assertEqual(self.daemon.rotated, [])

    def test_rotation_checks_ownership(self):
        account, device = self.account_with_device()
        other = self.desk.signup({"code": "friend-code-2"})[1]
        code, payload = self.desk.rotate_device(
            {"token": other["token"], "peer": device["peer"], "public_key": self.LINE})
        self.assertEqual(code, 404)
        self.assertIn("unknown device", payload["error"])
        code, payload = self.desk.rotate_device(
            {"token": "no-such-token", "peer": device["peer"], "public_key": self.LINE})
        self.assertEqual(code, 404)
        self.assertIn("unknown account token", payload["error"])
        self.assertEqual(self.daemon.rotated, [])

    def test_rotation_on_a_revoked_account_is_refused(self):
        account, device = self.account_with_device()
        self.desk.admin("/api/admin/revoke-account",
                        {"admin_token": "admin-secret", "token": account["token"]})
        code, payload = self.desk.rotate_device(
            {"token": account["token"], "peer": device["peer"], "public_key": self.LINE})
        self.assertEqual(code, 403)
        self.assertIn("revoked", payload["error"])
        self.assertEqual(self.daemon.rotated, [])

    def test_rotation_of_a_removed_device_is_refused(self):
        account, device = self.account_with_device()
        self.desk.remove_device({"token": account["token"], "peer": device["peer"]})
        code, payload = self.desk.rotate_device(
            {"token": account["token"], "peer": device["peer"], "public_key": self.LINE})
        self.assertEqual(code, 404)
        self.assertEqual(self.daemon.rotated, [])

    def test_rotation_of_a_legacy_device_works(self):
        # Pre-migration accounts carry their device in accounts.peer with no
        # peers row; the legacy column IS the device, and it rotates too.
        _, account = self.signup()
        self.desk.db.execute("UPDATE accounts SET peer='u0001-old' WHERE token=?",
                             (token_digest(account["token"]),))
        code, payload = self.desk.rotate_device(
            {"token": account["token"], "peer": "u0001-old", "public_key": self.LINE})
        self.assertEqual(code, 200)
        self.assertEqual(self.daemon.rotated, [("u0001-old", self.LINE)])

    def test_a_daemon_refusal_is_a_502_and_changes_nothing(self):
        account, device = self.account_with_device()
        self.daemon._refuse_rotate = True
        code, payload = self.desk.rotate_device(
            {"token": account["token"], "peer": device["peer"], "public_key": self.LINE})
        self.assertEqual(code, 502)
        self.assertIn("daemon refused", payload["error"])
        self.assertEqual(
            self.desk.db.execute(
                "SELECT COUNT(*) FROM peers WHERE status='active'").fetchone()[0], 1)

    def test_a_failed_finalize_is_reported_not_hidden(self):
        # The rotation happened; the old key is still accepted. Saying 502
        # would misname what did — the answer carries both facts (recovery:
        # see DaemonCli.rotate).
        account, device = self.account_with_device()
        self.daemon._refuse_finalize = True
        code, payload = self.desk.rotate_device(
            {"token": account["token"], "peer": device["peer"], "public_key": self.LINE})
        self.assertEqual(code, 200)
        self.assertIs(payload["finalized"], False)
        self.assertIn("old key", payload["warning"])
        self.assertIn("retry", payload["warning"])
        self.assertEqual(self.daemon.rotated, [(device["peer"], self.LINE)])

    def test_rotation_refuses_non_string_peer_and_token(self):
        # A JSON number/list/dict where a name belongs is a 400 naming the
        # field — not a sqlite bind error behind a 500, and not a 404 that
        # blames the device for the caller's typing (house rule, 6eb03da).
        account, device = self.account_with_device()
        for bad in (["u0001-x"], {"p": 1}, 123, True):
            with self.subTest(peer=bad):
                code, payload = self.desk.rotate_device(
                    {"token": account["token"], "peer": bad, "public_key": self.LINE})
                self.assertEqual(code, 400)
                self.assertIn("peer", payload["error"])
        for bad in (["tok"], {"t": 1}, 123):
            with self.subTest(token=bad):
                code, payload = self.desk.rotate_device(
                    {"token": bad, "peer": device["peer"], "public_key": self.LINE})
                self.assertEqual(code, 400)
                self.assertIn("token", payload["error"])
        self.assertEqual(self.daemon.rotated, [])

    def test_rotation_of_a_peer_the_daemon_does_not_have_is_a_502(self):
        # The desk's row is a record, not reality (ADR-0047 §1): a legacy
        # device already removed from the daemon cannot rotate — the CLI
        # refuses "no peer named", and the desk reports the refusal.
        _, account = self.signup()
        self.desk.db.execute("UPDATE accounts SET peer='u0001-old' WHERE token=?",
                             (token_digest(account["token"]),))
        self.daemon.missing_peers = ["u0001-old"]
        code, payload = self.desk.rotate_device(
            {"token": account["token"], "peer": "u0001-old", "public_key": self.LINE})
        self.assertEqual(code, 502)
        self.assertIn("daemon refused", payload["error"])


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
        # The burn records who consumed the code. A device-less account has
        # no peer, so its label stands in — NULL here would read as "unused".
        self.assertEqual(code_row["used_by"], row["label"])

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
        self.signup(code=minted["code"])
        token = self._token()
        code, payload = self.desk.voucher({"token": token, "code": minted["code"]})
        self.assertEqual(code, 403)
        self.assertIn("already used", payload["error"])

    def test_a_voucher_needs_an_active_account(self):
        token = self._token()
        self.desk.admin("/api/admin/revoke-account",
                        {"admin_token": "admin-secret", "token": token})
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
        account, device = self.account_with_device()
        code, _ = self.desk.admin("/api/admin/plan", {
            "admin_token": "admin-secret", "peer": device["peer"], "bytes_cap": 42})
        self.assertEqual(code, 200)
        self.assertEqual(self.desk.db.execute(
            "SELECT bytes_cap FROM accounts WHERE token=?",
            (token_digest(account["token"]),)).fetchone()[0], 42)

    def test_an_account_can_be_reinstated(self):
        # The way back after a quota fired on a mis-set cap.
        account, device = self.account_with_device()
        self.desk.db.execute("UPDATE accounts SET status='overquota' WHERE token=?",
                             (token_digest(account["token"]),))
        code, _ = self.desk.admin("/api/admin/plan", {
            "admin_token": "admin-secret", "peer": device["peer"], "status": "active"})
        self.assertEqual(code, 200)
        self.assertEqual(self.desk.db.execute(
            "SELECT status FROM accounts WHERE token=?",
            (token_digest(account["token"]),)).fetchone()[0], "active")

    def test_an_unknown_status_is_refused(self):
        _, device = self.account_with_device()
        code, payload = self.desk.admin("/api/admin/plan", {
            "admin_token": "admin-secret", "peer": device["peer"], "status": "banished"})
        self.assertEqual(code, 400)

    def test_a_deviceless_account_can_be_planned_by_token(self):
        # An account-only signup has no peer to address — the operator must
        # still be able to reach it, by its account number.
        _, account = self.signup()
        code, _ = self.desk.admin("/api/admin/plan", {
            "admin_token": "admin-secret", "token": account["token"], "bytes_cap": 42})
        self.assertEqual(code, 200)
        self.assertEqual(self.desk.db.execute(
            "SELECT bytes_cap FROM accounts WHERE token=?",
            (token_digest(account["token"]),)).fetchone()[0], 42)

    def test_a_deviceless_account_can_be_revoked_by_token(self):
        _, account = self.signup()
        code, _ = self.desk.admin("/api/admin/revoke-account", {
            "admin_token": "admin-secret", "token": account["token"]})
        self.assertEqual(code, 200)
        self.assertEqual(self.desk.db.execute(
            "SELECT status FROM accounts WHERE token=?",
            (token_digest(account["token"]),)).fetchone()["status"], "revoked")
        self.assertEqual(self.daemon.removed, [])  # nothing to remove

    def test_the_accounts_listing_carries_the_account_handle(self):
        # The listing carries the account's stored handle — since v7 that is
        # the number's digest, a stable correlation id that is not itself a
        # credential. To *act* on an account the operator addresses it by
        # peer, label or recovery code — the number is never read back.
        _, account = self.signup()
        code, payload = self.desk.admin("/api/admin/peers",
                                        {"admin_token": "admin-secret"})
        self.assertEqual(code, 200)
        self.assertEqual(payload["peers"][0]["token"],
                         token_digest(account["token"]))

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
        _, device = self.account_with_device()
        peer = device["peer"]
        code, _ = self.desk.admin("/api/admin/revoke", {
            "admin_token": "admin-secret", "peer": peer})
        self.assertEqual(code, 200)
        self.assertEqual(self.daemon.removed, [peer])

    def test_an_unknown_admin_endpoint_is_not_found(self):
        code, _ = self.desk.admin("/api/admin/nope", {"admin_token": "admin-secret"})
        self.assertEqual(code, 404)


class WhiteLabelConfigTests(DeskTestCase):
    """The install source and the repo link are the operator's, not the
    upstream project's: a desk someone else deploys must not send its users
    to KidIkaros. The defaults stay the upstream values, so an unconfigured
    desk renders exactly what it always did."""

    UPSTREAM_INSTALL = ("curl -fsSL -o /tmp/vallum-install.sh "
                        "https://raw.githubusercontent.com/KidIkaros/vallum/main/scripts/install.sh"
                        " && sudo bash /tmp/vallum-install.sh --from-release --install-only")

    def test_the_default_install_command_is_unchanged(self):
        code, payload = self.signup()
        self.assertEqual(code, 200)
        self.assertEqual(payload["install"], self.UPSTREAM_INSTALL)

    def test_a_configured_install_source_replaces_the_upstream_url(self):
        self.config.install_source = "https://vpn.example.com/install.sh"
        code, payload = self.signup()
        self.assertEqual(code, 200)
        self.assertIn("https://vpn.example.com/install.sh", payload["install"])
        self.assertNotIn("KidIkaros", payload["install"])
        self.assertNotIn("raw.githubusercontent", payload["install"])

    def test_the_cli_defaults_match_the_upstream_values(self):
        args = desk_module.parse_args(["--config", "/etc/vallum/server.toml"])
        self.assertEqual(
            args.install_source,
            "https://raw.githubusercontent.com/KidIkaros/vallum/main/scripts/install.sh")
        self.assertEqual(args.repo_url, "https://github.com/KidIkaros/vallum")

    def test_the_cli_flags_override_the_sources(self):
        # The flags ride VALLUM_DESK_EXTRA_ARGS in /etc/vallum/desk.env —
        # the unit's existing env path, so env and CLI are one knob.
        args = desk_module.parse_args([
            "--config", "/etc/vallum/server.toml",
            "--install-source", "https://vpn.example.com/install.sh",
            "--repo-url", "https://git.example.com/vallum"])
        self.assertEqual(args.install_source, "https://vpn.example.com/install.sh")
        self.assertEqual(args.repo_url, "https://git.example.com/vallum")


class WhiteLabelHttpTests(WireTestCase):
    """The served pages, not just the logic: when the operator configures
    their own install source and repo, zero hardcoded upstream references
    may remain in anything the desk serves."""

    def setUp(self):
        super().setUp()
        self.config.operator_name = "example tunnel"
        self.config.install_source = "https://vpn.example.com/install.sh"
        self.config.repo_url = "https://git.example.com/vallum"

    def get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as r:
            return r.status, r.read().decode()

    def test_the_index_serves_the_operators_install_source_and_repo(self):
        status, page = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn("https://vpn.example.com/install.sh", page)
        self.assertIn('href="https://git.example.com/vallum"', page)
        self.assertIn("git.example.com/vallum</a>", page)
        self.assertNotIn("KidIkaros", page)

    def test_the_account_page_serves_the_operators_install_source_and_repo(self):
        status, page = self.post("/signup", "code=friend-code-1",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertIn("https://vpn.example.com/install.sh", page)
        self.assertIn('href="https://git.example.com/vallum"', page)
        self.assertNotIn("KidIkaros", page)

    def test_the_signup_json_install_command_is_the_operators(self):
        status, body = self.post("/api/signup", '{"code":"friend-code-1"}',
                                 "application/json")
        self.assertEqual(status, 200)
        install = json.loads(body)["install"]
        self.assertIn("https://vpn.example.com/install.sh", install)
        self.assertNotIn("KidIkaros", install)

    def test_no_served_page_mentions_the_upstream_repo(self):
        # Every page a visitor can reach: the index, the account shell, the
        # account-created page, the ticket page (add-device), the account
        # page, and the error page. One upstream reference in any of them is
        # a leak.
        _, signup_body = self.post("/api/signup", '{"code":"friend-code-1"}',
                                   "application/json")
        token = json.loads(signup_body)["token"]
        pages = [self.get("/")[1], self.get("/account")[1]]
        pages.append(self.post("/signup", "code=friend-code-2",
                               "application/x-www-form-urlencoded")[1])
        pages.append(self.post("/account", f"token={token}",
                               "application/x-www-form-urlencoded")[1])
        pages.append(self.post("/account/device", f"token={token}&name=extra",
                               "application/x-www-form-urlencoded")[1])
        pages.append(self.post("/signup", "code=not-a-code",
                               "application/x-www-form-urlencoded")[1])
        for page in pages:
            self.assertNotIn("KidIkaros", page)
            self.assertNotIn("raw.githubusercontent", page)

    def test_the_error_page_carries_the_operator_name(self):
        # The one page that had no brand: a refusal is still the operator's
        # service speaking, not an anonymous upstream desk.
        status, page = self.post("/signup", "code=not-a-code",
                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 403)
        self.assertIn("example tunnel", page)

    def test_the_repo_link_is_html_escaped(self):
        # The URL is operator input now: an ampersand in a query string must
        # not break out of the href attribute's HTML.
        self.config.repo_url = "https://git.example.com/vallum?a=1&b=2"
        _, page = self.get("/")
        self.assertIn('href="https://git.example.com/vallum?a=1&amp;b=2"', page)


class AccountOnlyTests(DeskTestCase):
    """An account with no devices yet is a first-class row (ADR-0047): every
    reader answers truthfully about it, every operator path can reach it, and
    the first device enrols onto it without special-casing."""

    def test_the_account_view_reports_no_devices(self):
        _, account = self.signup()
        code, view = self.desk.account(account["token"])
        self.assertEqual(code, 200)
        self.assertEqual(view["devices"], [])
        self.assertEqual(view["conversion"],
                         {"devices_total": 0, "devices_connected": 0})
        self.assertEqual(view["bytes_used"], 0)  # no devices, no bytes — true

    def test_the_account_view_survives_a_down_daemon(self):
        _, account = self.signup()
        self.desk.daemon = FakeDaemon(refuse_counters=True, refuse_liveness=True)
        code, view = self.desk.account(account["token"])
        self.assertEqual(code, 200)
        self.assertIsNone(view["bytes_used"])
        self.assertEqual(view["devices"], [])

    def test_status_reports_no_peers(self):
        _, account = self.signup()
        code, payload = self.desk.status(account["token"])
        self.assertEqual(code, 200)
        self.assertEqual(payload["peers"], [])
        self.assertIsNone(payload["peer"])

    def test_the_funnel_counts_the_account_but_no_device(self):
        self.signup()
        funnel = self.desk.funnel()
        self.assertEqual(funnel["accounts"], {"active": 1})
        self.assertEqual(funnel["devices_total"], 0)

    def test_expiry_revokes_a_deviceless_account(self):
        # No peers to remove is not an error: the account row itself is what
        # expiry marks, and the sweep must finish the job.
        _, account = self.signup()
        self.desk.db.execute("UPDATE accounts SET expires='2020-01-01' WHERE token=?",
                             (token_digest(account["token"]),))
        actions = self.desk.sweep_once()
        self.assertEqual([a["reason"] for a in actions], ["expired"])
        self.assertNotIn("error", actions[0])
        self.assertEqual(self.daemon.removed, [])
        self.assertEqual(self.desk.db.execute(
            "SELECT status FROM accounts").fetchone()["status"], "expired")

    def test_the_first_device_enrols_on_a_deviceless_account(self):
        _, account = self.signup()
        code, device = self.desk.add_device({"token": account["token"], "name": "phone"})
        self.assertEqual(code, 200)
        self.assertEqual(device["peer"], "u0001-phone")
        _, view = self.desk.account(account["token"])
        self.assertEqual([d["peer"] for d in view["devices"]], ["u0001-phone"])

    def test_a_voucher_burns_its_code_on_a_deviceless_account(self):
        # The burn writes `used_by`; with no peer it must fall back to the
        # account label. A NULL burn reads as "unused" and the same code
        # redeems twice — the single-use invariant silently broken.
        _, account = self.signup()
        _, minted = self.desk._mint_code({"days": 30})
        code, _ = self.desk.voucher({"token": account["token"], "code": minted["code"]})
        self.assertEqual(code, 200)
        used_by = self.desk.db.execute(
            "SELECT used_by FROM codes WHERE code=?", (minted["code"],)).fetchone()["used_by"]
        self.assertIsNotNone(used_by)
        code, payload = self.desk.voucher({"token": account["token"], "code": minted["code"]})
        self.assertEqual(code, 403)
        self.assertIn("already used", payload["error"])

    def test_a_device_cannot_be_removed_from_a_deviceless_account(self):
        _, account = self.signup()
        code, payload = self.desk.remove_device({"token": account["token"], "peer": "u0001-x"})
        self.assertEqual(code, 404)

    def test_removing_a_device_needs_a_peer_name(self):
        # A missing peer must not slip past the ownership check: on a
        # new-contract account the legacy column is NULL, and `None != None`
        # is False — the old comparison would pass and call daemon.remove(None).
        _, account = self.signup()
        code, payload = self.desk.remove_device({"token": account["token"]})
        self.assertEqual(code, 400)
        self.assertIn("peer", payload["error"])
        self.assertEqual(self.daemon.removed, [])


class ReconciliationTests(DeskTestCase):
    """WS4d (ADR-0047 §1): the daemon is the source of truth for devices.

    The cap counts actual daemon peers plus live reservations, not desk rows
    alone: a ticket nobody redeemed must not burn a device slot for ever, and
    a daemon that cannot be asked must not cause a guess."""

    def _backdate(self, peer, seconds):
        old = (datetime.datetime.now(datetime.timezone.utc)
               - datetime.timedelta(seconds=seconds)).isoformat(timespec="seconds")
        with self.desk.lock:
            self.desk.db.execute("UPDATE peers SET created=? WHERE peer=?", (old, peer))

    def _status(self, peer):
        with self.desk.lock:
            return self.desk.db.execute(
                "SELECT status FROM peers WHERE peer=?", (peer,)).fetchone()[0]

    def test_ghost_reservation_is_released_and_frees_the_cap(self):
        self.config.device_cap = 2
        account, device = self.account_with_device(name="real")
        code, ghost = self.desk.add_device({"token": account["token"], "name": "ghost"})
        self.assertEqual(code, 200)
        self._backdate(ghost["peer"], 3600)
        self.daemon._liveness = {device["peer"]: 1700000000}  # only the real device exists
        # rows now == cap (2); without reconciliation this would 429
        code, payload = self.desk.add_device({"token": account["token"], "name": "new"})
        self.assertEqual(code, 200, payload)
        self.assertEqual(self._status(ghost["peer"]), "removed")

    def test_ghost_release_does_not_call_daemon_remove(self):
        account, device = self.account_with_device(name="real")
        code, ghost = self.desk.add_device({"token": account["token"], "name": "ghost"})
        self._backdate(ghost["peer"], 3600)
        self.daemon._liveness = {device["peer"]: 1700000000}
        self.desk.add_device({"token": account["token"], "name": "new"})
        # the peer is absent from the daemon: there is nothing to remove there
        self.assertNotIn(ghost["peer"], self.daemon.removed)

    def test_pending_reservation_within_ttl_is_kept(self):
        self.config.device_cap = 2
        account, device = self.account_with_device(name="real")
        code, pending = self.desk.add_device({"token": account["token"], "name": "pending"})
        self.assertEqual(code, 200)
        self.daemon._liveness = {device["peer"]: 1700000000}  # pending not yet joined
        code, payload = self.desk.add_device({"token": account["token"], "name": "new"})
        self.assertEqual(code, 429)  # real + pending == cap; a fresh ticket is not a ghost
        self.assertIn("device limit", payload["error"])
        self.assertEqual(self._status(pending["peer"]), "active")

    def test_redeemed_device_is_kept_regardless_of_age(self):
        self.config.device_cap = 1
        account, device = self.account_with_device(name="real")
        self._backdate(device["peer"], 100000)  # old, but present on the daemon
        self.daemon._liveness = {device["peer"]: 1700000000}
        code, payload = self.desk.add_device({"token": account["token"], "name": "new"})
        self.assertEqual(code, 429)  # the real device still counts
        self.assertEqual(self._status(device["peer"]), "active")

    def test_unreachable_daemon_releases_nothing(self):
        self.config.device_cap = 2
        account, device = self.account_with_device(name="real")
        code, ghost = self.desk.add_device({"token": account["token"], "name": "ghost"})
        self._backdate(ghost["peer"], 3600)
        self.daemon._refuse_liveness = True  # the daemon cannot be asked
        code, payload = self.desk.add_device({"token": account["token"], "name": "new"})
        self.assertEqual(code, 429)  # fail-closed: rows counted, no guess, no release
        self.assertEqual(self._status(ghost["peer"]), "active")

    def test_sweep_releases_ghost_reservations_of_active_accounts(self):
        account, device = self.account_with_device(name="real")
        code, ghost = self.desk.add_device({"token": account["token"], "name": "ghost"})
        self._backdate(ghost["peer"], 3600)
        self.daemon._liveness = {device["peer"]: 1700000000}
        actions = self.desk.sweep_once()
        self.assertTrue(any(a.get("peer") == ghost["peer"] and a.get("reason") == "unredeemed"
                            for a in actions), actions)
        self.assertEqual(self._status(ghost["peer"]), "removed")


class BrandTests(unittest.TestCase):
    """The desk pages carry the Vallum brandkit (obsidian + signal cyan + ◆),
    and the re-skin keeps the markup the rest of the suite reads intact."""

    def test_every_page_carries_the_brand(self):
        pages = [
            desk_module.index_page(False),
            desk_module.index_page(True),
            desk_module.account_created_page({"token": "t", "expires": "2026-12-03",
                                              "plan": "trial", "bytes_cap": 50 * 1024**3}),
            desk_module.ticket_page({"ticket": "x", "peer": "u0001-a", "token": "t",
                                     "expires": "2026-12-03", "plan": "trial",
                                     "bytes_cap": 50 * 1024**3}),
            desk_module.error_page("boom"),
            desk_module.account_shell_page(),
        ]
        for page in pages:
            self.assertIn("#39c5cf", page)                       # signal cyan
            self.assertIn("#0d1117", page)                       # obsidian
            self.assertIn("every boundary under watch", page)    # tagline footer
            self.assertIn("h1::before", page)                    # ◆ in CSS, not markup

    def test_the_reskin_keeps_the_h1_markup_plain(self):
        # the ◆ rides h1::before so the operator name stays readable markup
        self.assertIn("<h1>wingman tunnel</h1>",
                      desk_module.index_page(False, operator="wingman tunnel"))


if __name__ == "__main__":
    unittest.main()
