#!/usr/bin/env python3
"""Tests for the Vallum enrolment desk.

The desk's whole value is that its accounting is *right*: a quota that never
matches is a quota that never fires, and a passing expiry test makes that
look alive. So the tests are mostly about the accounting, and they run
against a fake daemon — the `Daemon` port is what makes that possible.

    python3 -m unittest discover -s service -p 'test_*.py'
"""

import importlib.util
import os
import tempfile
import unittest
from importlib.machinery import SourceFileLoader

DESK_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vallum-desk")
_spec = importlib.util.spec_from_loader("vallum_desk", SourceFileLoader("vallum_desk", DESK_PATH))
assert _spec is not None and _spec.loader is not None, "the desk module must load"
desk_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(desk_module)

Desk = desk_module.Desk
DeskConfig = desk_module.DeskConfig


class FakeDaemon(desk_module.Daemon):
    """A daemon that is a dictionary with a method or two."""

    def __init__(self, counters=None, refuse=False):
        self._counters = counters or {}
        self._refuse = refuse
        self.removed = []
        self.minted = []

    def mint_ticket(self, peer):
        if self._refuse:
            raise RuntimeError("the daemon said no")
        self.minted.append(peer)
        return f"vallum1-join:203.0.113.9:51922/{peer}/deadbeef/token/fingerprint"

    def counters(self):
        return dict(self._counters)

    def remove(self, peer):
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
