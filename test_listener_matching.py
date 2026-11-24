"""Regression tests for comparing configured ports with Linux ss output."""

import unittest

from rayzento_core import missing_listeners


class ListenerMatchingTests(unittest.TestCase):
    def test_accepts_ipv4_and_dual_stack_wildcards(self):
        expected = ["tcp 0.0.0.0:12001", "udp 0.0.0.0:12002", "tcp 0.0.0.0:12003"]
        observed = ["tcp *:12001", "udp *:12002", "tcp 0.0.0.0:12003"]
        self.assertEqual(missing_listeners(expected, observed), [])

    def test_requires_correct_address_protocol_and_port(self):
        expected = ["tcp 0.0.0.0:12001", "udp 0.0.0.0:12002", "tcp 127.0.0.1:12003"]
        observed = ["tcp [::]:12001", "tcp *:12002", "tcp *:12003", "udp *:12004"]
        self.assertEqual(missing_listeners(expected, observed), sorted(expected))

    def test_preserves_exact_observed_baseline_from_earlier_backup(self):
        self.assertEqual(missing_listeners(["tcp *:12001"], ["tcp *:12001"]), [])
        self.assertEqual(missing_listeners(["tcp *:12001"], ["tcp 0.0.0.0:12001"]), ["tcp *:12001"])
