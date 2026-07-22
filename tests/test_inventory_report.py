from __future__ import annotations

import hashlib
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

        self.assertEqual(report["schema_version"], "nodeutils.inventory.v2")
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

    def test_docker_service_probe_hint_extends_builtin_names(self) -> None:
        container = {
            "name": "edge-dnsmasq-primary",
            "image": "example/edge-dnsmasq:latest",
            "labels": {},
        }

        self.assertIsNone(nodeutils_collect.important_service_name(container))
        self.assertEqual(
            nodeutils_collect.important_service_name(
                container,
                {"service_probe_hints": {"dnsmasq": {}}},
            ),
            "dnsmasq",
        )

    def test_systemd_probe_hint_supports_nomad_and_node_exporter_units(self) -> None:
        config = {
            "service_probe_hints": {
                "nomad": {"systemd_unit": "nomad.service"},
                "prometheus-node-exporter": {"systemd_unit": "prometheus-node-exporter.service"},
            }
        }

        self.assertEqual(
            nodeutils_collect.important_service_name_from_systemd(
                {"unit": "nomad.service", "description": "HashiCorp agent"},
                config,
            ),
            "nomad",
        )
        self.assertEqual(
            nodeutils_collect.important_service_name_from_systemd(
                {"unit": "prometheus-node-exporter.service", "description": "Metrics"},
                config,
            ),
            "prometheus-node-exporter",
        )

    def test_observe_managed_file_present_reports_digest_size_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "records.conf"
            path.write_bytes(b"host-record=edge.test,192.0.2.10\n")

            entry = nodeutils_collect.observe_managed_file(str(path), "2026-07-22T00:00:00+00:00")

            self.assertEqual(entry["status"], "present")
            self.assertEqual(entry["path"], str(path))
            self.assertEqual(entry["size"], path.stat().st_size)
            self.assertEqual(entry["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(entry["checked_at"], "2026-07-22T00:00:00+00:00")

    def test_observe_managed_file_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "does-not-exist.conf"

            entry = nodeutils_collect.observe_managed_file(str(path), "2026-07-22T00:00:00+00:00")

            self.assertEqual(entry["status"], "missing")
            self.assertNotIn("sha256", entry)

    def test_observe_managed_file_too_large(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "huge.conf"
            path.write_bytes(b"0" * (nodeutils_collect.MAX_MANAGED_FILE_BYTES + 1))

            entry = nodeutils_collect.observe_managed_file(str(path), "2026-07-22T00:00:00+00:00")

            self.assertEqual(entry["status"], "too_large")
            self.assertNotIn("sha256", entry)

    def test_observe_managed_file_unreadable_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # A directory at the configured path is neither present-as-file nor missing.
            entry = nodeutils_collect.observe_managed_file(tmpdir, "2026-07-22T00:00:00+00:00")

            self.assertEqual(entry["status"], "missing")

    def test_managed_files_for_service_rejects_relative_path(self) -> None:
        config = {
            "service_probe_hints": {
                "dnsmasq": {"managed_files": {"records": {"path": "relative/records.conf"}}},
            }
        }

        results = nodeutils_collect.managed_files_for_service("dnsmasq", config, "2026-07-22T00:00:00+00:00")

        self.assertEqual(results, {})

    def test_managed_files_for_service_rejects_malformed_spec(self) -> None:
        config = {"service_probe_hints": {"dnsmasq": {"managed_files": {"records": "not-a-mapping"}}}}

        results = nodeutils_collect.managed_files_for_service("dnsmasq", config, "2026-07-22T00:00:00+00:00")

        self.assertEqual(results, {})

    def test_managed_files_for_service_accepts_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nintent-records.conf"
            path.write_bytes(b"host-record=edge.test,192.0.2.10\n")
            config = {"service_probe_hints": {"dnsmasq": {"managed_files": {"records": {"path": str(path)}}}}}

            results = nodeutils_collect.managed_files_for_service("dnsmasq", config, "2026-07-22T00:00:00+00:00")

            self.assertEqual(results["records"]["status"], "present")
            self.assertEqual(results["records"]["path"], str(path))

    def test_normalize_observed_services_attaches_managed_files_without_docker_or_systemd_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nintent-records.conf"
            path.write_bytes(b"host-record=edge.test,192.0.2.10\n")
            config = {
                "service_probe_hints": {
                    "dnsmasq": {"systemd_unit": "dnsmasq.service", "managed_files": {"records": {"path": str(path)}}},
                }
            }

            observed = nodeutils_collect.normalize_observed_services(config, {}, {}, "2026-07-22T00:00:00+00:00", None)

            self.assertIn("dnsmasq", observed)
            self.assertEqual(observed["dnsmasq"]["source"], "probe")
            self.assertEqual(observed["dnsmasq"]["managed_files"]["records"]["status"], "present")

    def test_normalize_observed_services_merges_managed_files_into_systemd_detected_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nintent-records.conf"
            path.write_bytes(b"host-record=edge.test,192.0.2.10\n")
            config = {
                "service_probe_hints": {
                    "dnsmasq": {"systemd_unit": "dnsmasq.service", "managed_files": {"records": {"path": str(path)}}},
                }
            }
            systemd = {
                "important_services": [
                    {"service": "dnsmasq", "unit": "dnsmasq.service", "state": "active", "sub_state": "running"},
                ]
            }

            observed = nodeutils_collect.normalize_observed_services(
                config, {}, systemd, "2026-07-22T00:00:00+00:00", None
            )

            self.assertEqual(observed["dnsmasq"]["source"], "systemd")
            self.assertEqual(observed["dnsmasq"]["state"], "active")
            self.assertEqual(observed["dnsmasq"]["managed_files"]["records"]["status"], "present")

    def test_no_file_content_ever_appears_in_a_managed_file_observation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nintent-records.conf"
            secret_line = "host-record=super-secret-hostname.example,192.0.2.10"
            path.write_text(secret_line + "\n")

            entry = nodeutils_collect.observe_managed_file(str(path), "2026-07-22T00:00:00+00:00")

            self.assertNotIn(secret_line, json.dumps(entry))


if __name__ == "__main__":
    unittest.main()
