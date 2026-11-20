#!/usr/bin/env python3
"""Tests for vallum-uri — the x-scheme-handler target. The handler is a
privilege boundary: a browser-supplied string becomes a root `vallum
join`, so what it accepts and what it refuses are what get pinned.

    python3 -m unittest service.test_vallum_uri
"""

import importlib.util
import os
import stat
import tempfile
import unittest
import urllib.parse
from importlib.machinery import SourceFileLoader

SERVICE_DIR = os.path.dirname(os.path.abspath(__file__))

_spec = importlib.util.spec_from_loader(
    "vallum_uri", SourceFileLoader("vallum_uri", os.path.join(SERVICE_DIR, "vallum-uri")))
assert _spec is not None and _spec.loader is not None
uri_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uri_module)

parse_uri = uri_module.parse_uri

TOKEN32 = "0123456789abcdef0123456789abcdef"
TICKET = ("vallum1-join:203.0.113.9:51922/laptop/"
          f"{TOKEN32}/aaaa-bbbb-cccc-dddd-eeee-ffff-0000-1111/aabbccdd")


def uri(ticket=TICKET, account=TOKEN32, desk=None):
    built = f"vallum://join?ticket={urllib.parse.quote(ticket, safe='')}&account={account}"
    if desk is not None:
        built += f"&desk={urllib.parse.quote(desk, safe='')}"
    return built


class ParseTests(unittest.TestCase):

    def test_a_real_uri_parses(self):
        ticket, account, desk = parse_uri(uri())
        self.assertEqual(ticket, TICKET)
        self.assertEqual(account, TOKEN32)
        self.assertIsNone(desk)  # a desk-less URI (older desk) still parses

    def test_the_scheme_is_checked(self):
        with self.assertRaises(ValueError):
            parse_uri(uri().replace("vallum://", "https://"))

    def test_only_join_is_served(self):
        with self.assertRaises(ValueError):
            parse_uri(uri().replace("/join?", "/exec?"))

    def test_a_missing_ticket_is_refused(self):
        with self.assertRaises(ValueError):
            parse_uri(f"vallum://join?account={TOKEN32}")

    def test_a_garbage_ticket_is_refused(self):
        with self.assertRaises(ValueError):
            parse_uri(uri(ticket="vallum1-join:not-a-ticket"))
        with self.assertRaises(ValueError):
            parse_uri(uri(ticket="vallum1-join:host:99999/l/i/t/f"))
        with self.assertRaises(ValueError):
            parse_uri(uri(ticket=TICKET.replace("/laptop/", "/bad name/")))
        with self.assertRaises(ValueError):
            # the invite id must be 32 hex — a path must not squeeze in
            parse_uri(uri(ticket=TICKET.replace(f"/{TOKEN32}/", "/../../etc/")))

    def test_a_missing_or_garbage_account_is_refused(self):
        with self.assertRaises(ValueError):
            parse_uri(f"vallum://join?ticket={urllib.parse.quote(TICKET)}")
        with self.assertRaises(ValueError):
            parse_uri(uri(account="not-hex"))

    def test_a_bare_hex_token_ticket_is_accepted(self):
        ticket, _, _ = parse_uri(uri(ticket=TICKET.replace(
            "aaaa-bbbb-cccc-dddd-eeee-ffff-0000-1111",
            "aaaabbbbccccddddeeeeffff00001111")))
        self.assertIn("aaaabbbb", ticket)

    def test_the_desk_origin_parses(self):
        _, _, desk = parse_uri(uri(desk="https://desk.wingman.gold"))
        self.assertEqual(desk, "https://desk.wingman.gold")
        _, _, desk = parse_uri(uri(desk="https://127.0.0.1:8400"))
        self.assertEqual(desk, "https://127.0.0.1:8400")

    def test_a_garbage_desk_origin_is_refused(self):
        # The endpoint is where the account token will be sent: an origin
        # that is not exactly https://host[:port] is a refusal, not a shrug.
        for bad in ("http://desk.wingman.gold",           # not https
                    "https://desk.wingman.gold/account",  # a path rides along
                    "https://user@desk.wingman.gold",     # userinfo
                    "https://desk.wingman.gold?x=1",      # a query
                    "javascript:alert(1)"):
            with self.assertRaises(ValueError):
                parse_uri(uri(desk=bad))


class MainTests(unittest.TestCase):
    """main() drives a stub `vallum` on PATH — the seam is exec."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.capture = os.path.join(self.tempdir.name, "capture")
        stub = os.path.join(self.tempdir.name, "vallum")
        with open(stub, "w") as f:
            f.write("#!/bin/sh\nread -r ticket\n"
                    "echo \"args:$* ticket:$ticket account:$VALLUM_ACCOUNT "
                    "desk:$VALLUM_DESK_ENDPOINT\" "
                    f"> {self.capture}\n")
        os.chmod(stub, 0o755)
        # Stub sudo so the dispatcher probe is deterministic: these tests
        # exercise the same-uid fallback, so the probe must report "no
        # passwordless dispatcher" regardless of the host's real sudo state.
        sudo_stub = os.path.join(self.tempdir.name, "sudo")
        with open(sudo_stub, "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(sudo_stub, 0o755)
        self.old_path = os.environ["PATH"]
        os.environ["PATH"] = f"{self.tempdir.name}:{self.old_path}"
        self.addCleanup(os.environ.__setitem__, "PATH", self.old_path)

    def read_capture(self):
        with open(self.capture) as f:
            return f.read()

    def test_the_ticket_rides_stdin_and_the_token_the_environment(self):
        code = uri_module.main([uri()])
        self.assertEqual(code, 0)
        out = self.read_capture()
        # `vallum join -` was exec'd; the ticket came over stdin; the
        # account number came through the environment — argv carries
        # nothing but `join -`, which `ps` is welcome to show.
        self.assertIn("args:join -", out)
        self.assertIn(f"ticket:{TICKET}", out)
        self.assertIn(f"account:{TOKEN32}", out)

    def test_the_desk_origin_rides_the_environment(self):
        # ADR-0046: the client records the desk it enrolled through as the
        # account's endpoint. The handler passes desk=<origin> to `vallum
        # join` as VALLUM_DESK_ENDPOINT — same-uid env, never argv.
        code = uri_module.main([uri(desk="https://desk.wingman.gold")])
        self.assertEqual(code, 0)
        out = self.read_capture()
        self.assertIn("args:join -", out)
        self.assertIn("desk:https://desk.wingman.gold", out)

    def test_a_desk_less_uri_sets_no_endpoint_even_over_a_stale_one(self):
        # Older desks emit no desk=; the enrolment must still work, and an
        # inherited endpoint must not leak into a desk-less join.
        os.environ["VALLUM_DESK_ENDPOINT"] = "https://stale.example"
        self.addCleanup(os.environ.__delitem__, "VALLUM_DESK_ENDPOINT")
        code = uri_module.main([uri()])
        self.assertEqual(code, 0)
        out = self.read_capture()
        self.assertIn(f"account:{TOKEN32}", out)
        self.assertIn("desk:\n", out)

    def test_a_garbage_desk_origin_never_reaches_the_client(self):
        code = uri_module.main([uri(desk="http://desk.wingman.gold")])
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(self.capture))

    def test_a_refused_uri_never_reaches_the_client(self):
        code = uri_module.main([f"vallum://exec?ticket=x&account={TOKEN32}"])
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(self.capture))


class PrivilegedJoinTests(unittest.TestCase):
    """When passwordless sudo grants the dispatcher, Connect enrols through it
    (root → service install + tunnel proof), so the single-use ticket buys a
    working tunnel. Ticket/token/desk ride stdin lines 1/2/3 (#32), not argv."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.capture = os.path.join(self.tempdir.name, "capture")
        sudo_stub = os.path.join(self.tempdir.name, "sudo")
        with open(sudo_stub, "w") as f:
            f.write("#!/bin/sh\n"
                    'if [ "$1" = "-n" ] && [ "$2" = "-l" ]; then exit 0; fi\n'
                    "read -r ticket\nread -r account\nread -r desk || desk=''\n"
                    f'echo "privileged ticket:$ticket account:$account desk:$desk" > {self.capture}\n'
                    "exit 0\n")
        os.chmod(sudo_stub, 0o755)
        self.old_path = os.environ["PATH"]
        os.environ["PATH"] = f"{self.tempdir.name}:{self.old_path}"
        self.addCleanup(os.environ.__setitem__, "PATH", self.old_path)

    def read_capture(self):
        with open(self.capture) as f:
            return f.read()

    def test_connect_enrols_through_the_dispatcher_with_stdin_channels(self):
        code = uri_module.main([uri(desk="https://desk.wingman.gold")])
        self.assertEqual(code, 0)
        out = self.read_capture()
        self.assertIn("privileged", out)
        self.assertIn(f"ticket:{TICKET}", out)
        self.assertIn(f"account:{TOKEN32}", out)
        self.assertIn("desk:https://desk.wingman.gold", out)

    def test_desk_less_uri_sends_no_third_line(self):
        code = uri_module.main([uri()])
        self.assertEqual(code, 0)
        out = self.read_capture()
        self.assertIn(f"account:{TOKEN32}", out)
        self.assertIn("desk:\n", out)


class AccountHandoffTests(unittest.TestCase):
    """vallum://account (ADR-0047 Q4) records the account client-side; no device
    is enrolled, and the token never sits in argv."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.old_xdg = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self.tempdir.name
        self.addCleanup(self._restore_xdg)

    def _restore_xdg(self):
        if self.old_xdg is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self.old_xdg

    def _config(self):
        return os.path.join(self.tempdir.name, "vallum", "account.toml")

    def test_records_the_account_config_0600(self):
        code = uri_module.main(
            [f"vallum://account?token={TOKEN32}&desk=https://desk.wingman.gold"])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(self._config()))
        self.assertEqual(os.stat(self._config()).st_mode & 0o777, 0o600)
        with open(self._config()) as f:
            text = f.read()
        self.assertIn(f'token = "{TOKEN32}"', text)
        self.assertIn('endpoint = "https://desk.wingman.gold"', text)

    def test_desk_less_account_records_no_endpoint(self):
        code = uri_module.main([f"vallum://account?token={TOKEN32}"])
        self.assertEqual(code, 0)
        with open(self._config()) as f:
            self.assertNotIn("endpoint", f.read())

    def test_garbage_account_token_is_refused(self):
        self.assertEqual(uri_module.main(["vallum://account?token=nothex"]), 2)

    def test_garbage_desk_is_refused(self):
        self.assertEqual(uri_module.main(
            [f"vallum://account?token={TOKEN32}&desk=http://desk.example.com"]), 2)


if __name__ == "__main__":
    unittest.main()
