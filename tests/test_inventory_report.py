from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import nodeutils_collect


class InventoryReportTests(unittest.TestCase):
    def test_build_inventory_report_has_versioned_envelope(self) -> None:
        inventory = {
            "collected_at": "2026-06-21T00:00:00+00:00",
            "system": "Linux",
            "hostname": "pc1",
            "fqdn": "pc1.example.local",
            "serial_number": "abc123",
            "os_name": "Ubuntu",
            "os_version": "24.04",
            "kernel_version": "6.8",
            "architecture": "x86_64",
            "cpu_model": "Example CPU",
            "cpu_logical_cores": 8,
            "memory_gb": 32,
            "disk": {"root_total_gb": 512},
            "services": {"docker": {"engine_state": "not_installed"}},
        }

        with mock.patch.object(nodeutils_collect, "get_machine_id", return_value="machine-1"):
            report = nodeutils_collect.build_inventory_report(
                {"owner": "eiji", "purpose": "local-ai"},
                inventory,
            )

        self.assertEqual(report["schema_version"], "nodeutils.inventory.v1")
        self.assertEqual(report["collector"]["command"], "collect")
        self.assertEqual(report["identity"]["hostname"], "pc1")
        self.assertEqual(report["identity"]["machine_id"], "machine-1")
        self.assertEqual(report["facts"]["cpu"]["logical_cores"], 8)
        self.assertNotIn("service_roles", report["self_reported"])
        self.assertNotIn("preferred_services", report["self_reported"])
        self.assertNotIn("role", report["self_reported"])
        self.assertNotIn("location", report["self_reported"])

    def test_suspicious_keys_are_redacted(self) -> None:
        report = nodeutils_collect.bounded_value({"nested": {"api_token": "secret-value"}})

        self.assertEqual(report["nested"]["api_token"], "[redacted]")

    def test_write_output_uses_private_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "inventory.json"
            nodeutils_collect.write_output(output_path, json.dumps({"ok": True}))

            mode = stat.S_IMODE(output_path.stat().st_mode)
            self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
