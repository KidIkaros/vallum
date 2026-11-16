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


def uri(ticket=TICKET, account=TOKEN32):
    return f"vallum://join?ticket={urllib.parse.quote(ticket, safe='')}&account={account}"


class ParseTests(unittest.TestCase):

    def test_a_real_uri_parses(self):
        ticket, account = parse_uri(uri())
        self.assertEqual(ticket, TICKET)
        self.assertEqual(account, TOKEN32)

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
        ticket, _ = parse_uri(uri(ticket=TICKET.replace(
            "aaaa-bbbb-cccc-dddd-eeee-ffff-0000-1111",
            "aaaabbbbccccddddeeeeffff00001111")))
        self.assertIn("aaaabbbb", ticket)


class MainTests(unittest.TestCase):
    """main() drives a stub `vallum` on PATH — the seam is exec."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.capture = os.path.join(self.tempdir.name, "capture")
        stub = os.path.join(self.tempdir.name, "vallum")
        with open(stub, "w") as f:
            f.write("#!/bin/sh\nread -r ticket\n"
                    "echo \"args:$* ticket:$ticket account:$VALLUM_ACCOUNT\" "
                    f"> {self.capture}\n")
        os.chmod(stub, 0o755)
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

    def test_a_refused_uri_never_reaches_the_client(self):
        code = uri_module.main([f"vallum://exec?ticket=x&account={TOKEN32}"])
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(self.capture))


if __name__ == "__main__":
    unittest.main()
