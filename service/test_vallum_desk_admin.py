#!/usr/bin/env python3
"""Tests for vallum-desk-admin — the operator CLI — against a live desk
on an ephemeral port with the fake daemon underneath, so each test
proves the CLI actually reached the right endpoint.

    python3 -m unittest service.test_vallum_desk_admin
"""

import contextlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from importlib.machinery import SourceFileLoader

SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))


def load(module_name, filename):
    spec = importlib.util.spec_from_loader(
        module_name, SourceFileLoader(module_name, os.path.join(SERVICE_DIR, filename)))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


desk_module = load("vallum_desk", "vallum-desk")
admin_module = load("vallum_desk_admin", "vallum-desk-admin")
sys.path.insert(0, SERVICE_DIR)
from test_vallum_desk import FakeDaemon  # noqa: E402  (same service dir)


class AdminCliTests(unittest.TestCase):
    """The CLI end-to-end over HTTP — the mapping is what can rot."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.token_file = os.path.join(self.tempdir.name, "admin-token")
        with open(self.token_file, "w") as f:
            f.write("admin-secret\n")
        codes = os.path.join(self.tempdir.name, "codes.txt")
        with open(codes, "w") as f:
            f.write("friend-code-1\n")
        config = desk_module.DeskConfig(
            state=os.path.join(self.tempdir.name, "desk.sqlite"),
            codes=codes, admin_token="admin-secret",
            trial_days=14, trial_bytes=1000, sweep_secs=300,
            config="/etc/vallum/server.toml", bind="127.0.0.1", port=0)
        self.daemon = FakeDaemon()
        self.desk = Desk = desk_module.Desk(config, self.daemon)
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), desk_module.make_handler(Desk))
        self.addCleanup(self.server.shutdown)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            admin_module.main([
                "--desk", self.url, "--admin-token-file", self.token_file, *argv])
        # The serving desk's request log goes to stdout too; it is not the
        # CLI's output, so it stays out of what the tests assert on.
        return "\n".join(line for line in out.getvalue().splitlines()
                         if not line.startswith("desk:"))

    def signup(self, code="friend-code-1"):
        status, payload = self.desk.signup({"code": code})
        assert status == 200
        return payload

    def signup_with_device(self, code="friend-code-1", name="friend"):
        payload = self.signup(code)
        status, device = self.desk.add_device({"token": payload["token"], "name": name})
        assert status == 200
        return payload, device

    def test_mint_code_carries_the_payload_args(self):
        out = self.cli("mint-code", "--days", "30", "--gib", "2", "--plan", "plus")
        code = out.splitlines()[0].strip()
        row = self.desk.db.execute(
            "SELECT days, bytes, plan FROM codes WHERE code=?", (code,)).fetchone()
        self.assertEqual((row["days"], row["bytes"], row["plan"]),
                         (30, 2 * 1024 ** 3, "plus"))

    def test_mint_code_carries_device_slots(self):
        out = self.cli("mint-code", "--devices", "10", "--plan", "plus")
        code = out.splitlines()[0].strip()
        row = self.desk.db.execute(
            "SELECT devices, plan FROM codes WHERE code=?", (code,)).fetchone()
        self.assertEqual((row["devices"], row["plan"]), (10, "plus"))

    def test_queue_reports_seats_and_the_fifo(self):
        self.desk.config.open_signup = True
        self.desk.config.max_active_accounts = 1
        self.desk.signup({}, client_ip="198.51.100.1")
        self.desk.signup({}, client_ip="198.51.100.2")
        out = self.cli("queue")
        self.assertIn("1/1 active", out)
        self.assertIn("0 free", out)
        self.assertIn("1 queued", out)
        self.assertIn("#1 account-2", out)

    def test_promote_activates_a_queued_account(self):
        self.desk.config.open_signup = True
        self.desk.config.max_active_accounts = 0
        self.desk.signup({}, client_ip="198.51.100.9")
        out = self.cli("promote", "--label", "account-1")
        self.assertIn("account-1 active", out)
        row = self.desk.db.execute("SELECT status FROM accounts WHERE id=1").fetchone()
        self.assertEqual(row["status"], "active")

    def test_set_plan_changes_the_device_allowance(self):
        payload = self.signup()
        out = self.cli("set-plan", "--token", payload["token"], "--device-cap", "9")
        row = self.desk.db.execute("SELECT device_cap FROM accounts").fetchone()
        self.assertEqual(row["device_cap"], 9)

    def test_accounts_lists_the_accounts(self):
        payload = self.signup()
        out = self.cli("accounts")
        self.assertIn("account-1", out)  # the label identifies the account
        self.assertIn("trial", out)
        # The human view masks the stored handle — a credential must not
        # land in scrollback or CI logs; --json carries it in full. Since
        # v7 the stored handle is the number's digest, never the number.
        self.assertNotIn(payload["token"], out)
        self.assertIn(desk_module.token_digest(payload["token"])[:8], out)

    def test_devices_lists_each_account_device(self):
        payload = self.signup()
        self.desk.add_device({"token": payload["token"], "name": "friend"})
        self.desk.add_device({"token": payload["token"], "name": "laptop"})
        out = self.cli("devices")
        self.assertIn("u0001-friend", out)
        self.assertIn("u0002-laptop", out)

    def test_codes_lists_minted_codes(self):
        self.cli("mint-code")
        out = self.cli("codes")
        row = self.desk.db.execute("SELECT code FROM codes").fetchone()
        self.assertIn(row["code"], out)

    def test_json_mode_emits_parseable_output(self):
        payload = self.signup()
        out = self.cli("--json", "accounts")
        listing = json.loads(out)
        self.assertEqual(listing["peers"][0]["label"], "account-1")
        self.assertEqual(listing["peers"][0]["token"],
                         desk_module.token_digest(payload["token"]))

    def test_set_plan_changes_the_account_row(self):
        self.signup_with_device()
        self.cli("set-plan", "--peer", "u0001-friend",
                 "--plan", "plus", "--bytes-cap", "9000")
        row = self.desk.db.execute("SELECT plan, bytes_cap FROM accounts").fetchone()
        self.assertEqual((row["plan"], row["bytes_cap"]), ("plus", 9000))

    def test_set_plan_by_token_reaches_a_deviceless_account(self):
        payload = self.signup()
        self.cli("set-plan", "--token", payload["token"], "--bytes-cap", "9000")
        row = self.desk.db.execute("SELECT bytes_cap FROM accounts").fetchone()
        self.assertEqual(row["bytes_cap"], 9000)

    def test_set_plan_by_token_file_keeps_the_number_out_of_argv(self):
        payload = self.signup()
        number_file = os.path.join(self.tempdir.name, "account-number")
        with open(number_file, "w") as f:
            f.write(payload["token"] + "\n")
        self.cli("set-plan", "--token-file", number_file, "--bytes-cap", "9000")
        row = self.desk.db.execute("SELECT bytes_cap FROM accounts").fetchone()
        self.assertEqual(row["bytes_cap"], 9000)

    def test_set_plan_needs_exactly_one_of_peer_and_token(self):
        self.signup()
        with self.assertRaises(SystemExit) as raised:
            self.cli("set-plan", "--peer", "u0001-friend", "--token", "x",
                     "--bytes-cap", "1")
        self.assertIn("exactly one", str(raised.exception))
        with self.assertRaises(SystemExit) as raised:
            self.cli("set-plan", "--bytes-cap", "1")
        self.assertIn("exactly one", str(raised.exception))

    def test_revoke_removes_one_device(self):
        self.signup_with_device()
        self.cli("revoke", "--peer", "u0001-friend")
        self.assertEqual(self.daemon.removed, ["u0001-friend"])

    def test_revoke_account_removes_every_device(self):
        payload = self.signup()
        self.desk.add_device({"token": payload["token"], "name": "friend"})
        self.desk.add_device({"token": payload["token"], "name": "laptop"})
        self.cli("revoke", "--peer", "u0001-friend", "--account")
        self.assertEqual(sorted(self.daemon.removed), ["u0001-friend", "u0002-laptop"])

    def test_revoke_account_by_token_reaches_a_deviceless_account(self):
        payload = self.signup()
        self.cli("revoke", "--token", payload["token"], "--account")
        row = self.desk.db.execute("SELECT status FROM accounts").fetchone()
        self.assertEqual(row["status"], "revoked")
        self.assertEqual(self.daemon.removed, [])

    def test_revoke_account_by_token_file(self):
        payload = self.signup()
        number_file = os.path.join(self.tempdir.name, "account-number")
        with open(number_file, "w") as f:
            f.write(payload["token"] + "\n")
        self.cli("revoke", "--token-file", number_file, "--account")
        row = self.desk.db.execute("SELECT status FROM accounts").fetchone()
        self.assertEqual(row["status"], "revoked")

    def test_reset_token_prints_a_new_number_and_retires_the_old(self):
        payload = self.signup()
        old = payload["token"]
        out = self.cli("reset-token", "--token", old)
        # The column is a digest (v7): the only place the new number exists
        # in plaintext is the stdout it is shown on, once.
        new = re.search(r"[0-9a-f]{32}", out).group()
        self.assertNotEqual(new, old)
        self.assertIn(new, out)  # the new number is shown once, on stdout
        self.assertEqual(self.desk.status(old)[0], 404)
        self.assertEqual(self.desk.status(new)[0], 200)

    def test_reset_token_by_peer_reaches_the_account(self):
        payload, device = self.signup_with_device()
        out = self.cli("reset-token", "--peer", device["peer"])
        new = re.search(r"[0-9a-f]{32}", out).group()
        self.assertNotEqual(new, payload["token"])

    def test_reset_token_by_token_file_keeps_the_number_out_of_ps(self):
        payload = self.signup()
        number_file = os.path.join(self.tempdir.name, "account-number")
        with open(number_file, "w") as f:
            f.write(payload["token"] + "\n")
        out = self.cli("reset-token", "--token-file", number_file)
        new = re.search(r"[0-9a-f]{32}", out).group()
        self.assertNotEqual(new, payload["token"])

    def test_reset_token_by_recovery_code_proves_ownership(self):
        payload = self.signup()
        old = payload["token"]
        out = self.cli("reset-token", "--recovery-code", payload["recovery_code"])
        new = re.search(r"[0-9a-f]{32}", out).group()
        self.assertNotEqual(new, old)
        self.assertIn(new, out)
        self.assertEqual(self.desk.status(old)[0], 404)

    def test_per_device_revoke_needs_a_peer(self):
        payload = self.signup()
        with self.assertRaises(SystemExit) as raised:
            self.cli("revoke", "--token", payload["token"])
        self.assertIn("--peer", str(raised.exception))

    def test_sweep_runs_an_enforcement_pass(self):
        self.signup_with_device()
        self.desk.db.execute("UPDATE accounts SET expires='2000-01-01'")
        self.cli("sweep")
        self.assertEqual(self.daemon.removed, ["u0001-friend"])

    def test_a_bad_token_surfaces_the_desks_refusal(self):
        with open(self.token_file, "w") as f:
            f.write("wrong\n")
        with self.assertRaises(SystemExit) as raised:
            self.cli("accounts")
        self.assertIn("bad admin token", str(raised.exception))

    def test_an_unreachable_desk_reports_the_connection_error(self):
        with self.assertRaises(SystemExit) as raised:
            admin_module.main(["--desk", "http://127.0.0.1:1",
                               "--admin-token-file", self.token_file, "accounts"])
        self.assertIn("cannot reach", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
