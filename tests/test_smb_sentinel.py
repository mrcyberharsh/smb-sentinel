"""Unit tests for SMB Sentinel inventory and scope validation."""
import tempfile
import unittest
from pathlib import Path

import history
import scanner


class ScopeTests(unittest.TestCase):
    def test_accepts_small_private_ipv4_range(self):
        hosts = scanner.ips_in_cidr("192.168.10.0/30")
        self.assertEqual(len(hosts), 2)

    def test_rejects_public_and_oversized_ranges(self):
        for cidr in ("8.8.8.0/24", "192.168.0.0/16", "2001:db8::/64"):
            with self.subTest(cidr=cidr), self.assertRaises(ValueError):
                scanner.ips_in_cidr(cidr)


class HistoryTests(unittest.TestCase):
    def test_saves_sanitized_scan_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "history.json"
            summary = history.save_snapshot({
                "192.168.1.10": {
                    "risk_level": "high",
                    "findings": ["SMBv1 is enabled."],
                    "port_open": True,
                    "smb1_enabled": True,
                    "password": "must-not-be-saved",
                }
            }, path)
            stored = history.load_history(path)
            self.assertEqual(summary["host_count"], 1)
            self.assertEqual(stored[0]["high_count"], 1)
            self.assertNotIn("password", str(stored))


if __name__ == "__main__":
    unittest.main()
