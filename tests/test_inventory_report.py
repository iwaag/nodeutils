from __future__ import annotations

import hashlib
import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import nodeutils_collect
import service_endpoint_probes

GOLDEN_DNSMASQ_SHA256 = "c25e51c4efce07281e580dcfb1ecad73d666a70310f87cd28ad448241215e592"


class InventoryReportTests(unittest.TestCase):
    def test_cross_repository_dnsmasq_v5_golden_digest(self) -> None:
        """Hash the shared deterministic nctl artifact as a host would."""
        path = Path(__file__).parent / "fixtures" / "dnsmasq-v5-golden.conf"

        observed = nodeutils_collect.observe_managed_file(str(path), "2026-07-22T00:00:00+00:00")

        self.assertEqual(observed["status"], "present")
        self.assertEqual(observed["sha256"], GOLDEN_DNSMASQ_SHA256)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), GOLDEN_DNSMASQ_SHA256)

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

    def test_docker_compose_service_wins_over_container_name_substrings(self) -> None:
        container = {
            "name": "nautobot-redis",
            "image": "redis:7",
            "labels": {"com.docker.compose.service": "redis"},
        }

        self.assertEqual(
            nodeutils_collect.important_service_name(
                container,
                {"service_probe_hints": {"nautobot": {}, "redis": {}}},
            ),
            "redis",
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

    def test_systemd_fallback_requires_exact_unit_stem_not_substring(self) -> None:
        self.assertIsNone(
            nodeutils_collect.important_service_name_from_systemd(
                {"unit": "prometheus-node-exporter.service", "description": "Prometheus Node Exporter"},
                {},
            )
        )
        self.assertIsNone(
            nodeutils_collect.important_service_name_from_systemd(
                {"unit": "cron.service", "description": "Runs the prometheus backup job"},
                {},
            )
        )
        self.assertEqual(
            nodeutils_collect.important_service_name_from_systemd(
                {"unit": "prometheus.service", "description": "Monitoring system"},
                {},
            ),
            "prometheus",
        )
        self.assertEqual(
            nodeutils_collect.important_service_name_from_systemd(
                {"unit": "Nautobot.service", "description": ""},
                {},
            ),
            "nautobot",
        )

    def test_node_agent_linux_user_unit_reports_active_and_inactive_states(self) -> None:
        config = {"service_probe_hints": {"node-agent": {}}}
        unit_output = "opencode-agent.service loaded inactive dead OpenCode node agent\n"

        with (
            mock.patch.object(nodeutils_collect.platform, "system", return_value="Linux"),
            mock.patch.object(nodeutils_collect.shutil, "which", return_value="/usr/bin/systemctl"),
            mock.patch.object(nodeutils_collect, "_node_agent_version", return_value="1.18.10"),
            mock.patch.object(nodeutils_collect, "run_command", return_value=unit_output) as command,
        ):
            summary = nodeutils_collect.get_user_service_summary(config, "2026-07-31T00:00:00+00:00")

        self.assertTrue(summary["available"])
        self.assertEqual(summary["important_services"][0]["state"], "inactive")
        self.assertEqual(summary["important_services"][0]["version"], "1.18.10")
        self.assertEqual(command.call_args.args[0][:3], ["systemctl", "--user", "list-units"])

    def test_ollama_macos_launchd_service_is_observed_when_requested(self) -> None:
        config = {"service_probe_hints": {"ollama": {}}}

        with (
            mock.patch.object(nodeutils_collect.platform, "system", return_value="Darwin"),
            mock.patch.object(nodeutils_collect.shutil, "which", return_value="/bin/launchctl"),
            mock.patch.object(nodeutils_collect, "_node_agent_version", return_value=None),
            mock.patch.object(nodeutils_collect, "run_command", return_value="123\t0\tcom.ollama.ollama") as command,
        ):
            summary = nodeutils_collect.get_user_service_summary(config, "2026-07-31T00:00:00+00:00")

        self.assertTrue(summary["available"])
        self.assertEqual(summary["important_services"], [
            {"service": "ollama", "label": "com.ollama.ollama", "state": "active"}
        ])
        self.assertEqual(command.call_args.args[0], ["launchctl", "list", "com.ollama.ollama"])

    def test_ollama_process_is_observed_when_no_launchd_label_exists(self) -> None:
        config = {"service_probe_hints": {"ollama": {}}}

        with (
            mock.patch.object(nodeutils_collect.platform, "system", return_value="Darwin"),
            mock.patch.object(nodeutils_collect.shutil, "which", return_value="/bin/launchctl"),
            mock.patch.object(nodeutils_collect, "_node_agent_version", return_value=None),
            mock.patch.object(nodeutils_collect, "run_command", side_effect=[None, "123\n"]) as command,
        ):
            summary = nodeutils_collect.get_user_service_summary(config, "2026-07-31T00:00:00+00:00")

        self.assertEqual(summary["important_services"], [
            {"service": "ollama", "process": "ollama", "state": "active"}
        ])
        self.assertEqual(command.call_args.args[0], ["pgrep", "-x", "ollama"])

    def test_hinted_plain_user_process_is_observed_on_linux(self) -> None:
        config = {
            "service_probe_hints": {
                "swarmui": {"process_pattern": "StabilityMatrix.*SwarmUI"},
                "comfyui": {"process": "comfyui"},
            }
        }

        with (
            mock.patch.object(nodeutils_collect.platform, "system", return_value="Linux"),
            mock.patch.object(nodeutils_collect.shutil, "which", return_value="/usr/bin/systemctl"),
            mock.patch.object(nodeutils_collect, "_node_agent_version", return_value=None),
            mock.patch.object(nodeutils_collect, "run_command", side_effect=["4242\n", None]) as command,
        ):
            summary = nodeutils_collect.get_user_service_summary(config, "2026-08-06T00:00:00+00:00")

        self.assertTrue(summary["available"])
        self.assertEqual(summary["important_services"], [
            {"service": "comfyui", "process": "comfyui", "state": "active"}
        ])
        self.assertEqual(
            [call.args[0] for call in command.call_args_list],
            [["pgrep", "-x", "comfyui"], ["pgrep", "-f", "StabilityMatrix.*SwarmUI"]],
        )

    def test_unhinted_services_probe_no_processes(self) -> None:
        with (
            mock.patch.object(nodeutils_collect.platform, "system", return_value="Linux"),
            mock.patch.object(nodeutils_collect, "run_command") as command,
        ):
            summary = nodeutils_collect.get_user_service_summary(
                {"service_probe_hints": {"grafana": {}}}, "2026-08-06T00:00:00+00:00"
            )

        self.assertFalse(summary["available"])
        self.assertEqual(summary["important_services"], [])
        command.assert_not_called()

    def test_node_agent_user_service_is_normalized_without_configuration_contents(self) -> None:
        observed = nodeutils_collect.normalize_observed_services(
            {"service_probe_hints": {"node-agent": {}}}, {}, {}, "2026-07-31T00:00:00+00:00", None,
            {"important_services": [{"service": "node-agent", "unit": "opencode-agent.service", "state": "active", "version": "1.18.10"}]},
        )

        self.assertEqual(observed["node-agent"]["source"], "systemd_user")
        self.assertEqual(observed["node-agent"]["state"], "active")
        self.assertEqual(observed["node-agent"]["version"], "1.18.10")

    def test_hinted_http_check_registers_active_service(self) -> None:
        # autotask_intent Step 2: the probe paths come from the rendered
        # `checks` hint, not from any service-name-keyed table.
        response = mock.MagicMock()
        response.status = 200
        response.__enter__.return_value = response
        with mock.patch.object(
            service_endpoint_probes.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            observed = nodeutils_collect.normalize_observed_services(
                {
                    "service_probe_hints": {
                        "ollama": {
                            "endpoint": "http://agstudio.home.arpa:11434",
                            "checks": [{"kind": "http", "paths": ["/v1/models", "/api/tags"]}],
                        }
                    }
                },
                {}, {}, "2026-07-31T00:00:00+00:00", None,
            )

        self.assertEqual(observed["ollama"]["state"], "active")
        self.assertEqual(observed["ollama"]["source"], "http_probe")
        self.assertEqual(observed["ollama"]["endpoint"], "http://agstudio.home.arpa:11434")
        self.assertEqual(
            observed["ollama"]["checks"],
            [{"kind": "http", "endpoint": "http://agstudio.home.arpa:11434", "status": 200}],
        )
        urlopen.assert_called_once_with("http://agstudio.home.arpa:11434/v1/models", timeout=3)

    def test_hinted_http_checks_probe_each_service_independently(self) -> None:
        response = mock.MagicMock()
        response.status = 200
        response.__enter__.return_value = response
        with mock.patch.object(
            service_endpoint_probes.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            observed = nodeutils_collect.normalize_observed_services(
                {
                    "service_probe_hints": {
                        "swarmui": {"endpoint": "http://agpc.local:7801", "checks": [{"kind": "http", "paths": ["/"]}]},
                        "comfyui": {"endpoint": "http://127.0.0.1:7821", "checks": [{"kind": "http", "paths": ["/"]}]},
                    }
                },
                {}, {}, "2026-08-02T00:00:00+00:00", None,
            )

        self.assertEqual(observed["swarmui"]["state"], "active")
        self.assertEqual(observed["swarmui"]["source"], "http_probe")
        self.assertEqual(observed["comfyui"]["state"], "active")
        self.assertEqual(observed["comfyui"]["source"], "http_probe")
        self.assertEqual(
            urlopen.call_args_list,
            [
                mock.call("http://agpc.local:7801/", timeout=3),
                mock.call("http://127.0.0.1:7821/", timeout=3),
            ],
        )

    def test_file_exists_check_reports_present_and_missing_states(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            observed = nodeutils_collect.normalize_observed_services(
                {
                    "service_probe_hints": {
                        "swarmui": {"checks": [{"kind": "file_exists", "path": tmpdir}]},
                        "heartbeat-cron": {
                            "checks": [{"kind": "file_exists", "path": str(Path(tmpdir) / "does-not-exist")}]
                        },
                    }
                },
                {}, {}, "2026-08-06T00:00:00+00:00", None,
            )

        self.assertEqual(observed["swarmui"]["state"], "present")
        self.assertEqual(observed["swarmui"]["source"], "check:file_exists")
        self.assertEqual(
            observed["swarmui"]["checks"],
            [{"kind": "file_exists", "path": tmpdir, "status": "present"}],
        )
        # A missing file is positive evidence the check ran, not a silent
        # no-entry: the entry exists with state=missing and the check result.
        self.assertEqual(observed["heartbeat-cron"]["state"], "missing")
        self.assertEqual(observed["heartbeat-cron"]["source"], "check:file_exists")
        self.assertEqual(
            observed["heartbeat-cron"]["checks"][0]["status"], "missing",
        )

    def test_file_exists_check_does_not_override_running_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            observed = nodeutils_collect.normalize_observed_services(
                {"service_probe_hints": {"swarmui": {"checks": [{"kind": "file_exists", "path": tmpdir}]}}},
                {}, {}, "2026-08-06T00:00:00+00:00", None,
                {"important_services": [{"service": "swarmui", "process": "StabilityMatrix.*SwarmUI", "state": "active"}]},
            )

        self.assertEqual(observed["swarmui"]["state"], "active")
        self.assertEqual(observed["swarmui"]["source"], "process")
        self.assertEqual(
            observed["swarmui"]["checks"],
            [{"kind": "file_exists", "path": tmpdir, "status": "present"}],
        )

    def test_cron_registered_check_reports_present_and_missing_states(self) -> None:
        # autotask_intent ex1: registration proof joins existence proof. A
        # registered crontab line yields present; with the script on disk but
        # no crontab entry the placement state must be missing -- existence
        # alone no longer reads as converged.
        with tempfile.TemporaryDirectory() as tmpdir:
            script = str(Path(tmpdir) / "heartbeat.sh")
            Path(script).write_text("#!/bin/sh\n")
            hints = {
                "service_probe_hints": {
                    "heartbeat-cron": {
                        "checks": [
                            {"kind": "file_exists", "path": script},
                            {"kind": "cron_registered", "path": script},
                        ]
                    }
                }
            }
            with mock.patch.object(
                nodeutils_collect, "crontab_registration_status", return_value="present"
            ) as status:
                observed = nodeutils_collect.normalize_observed_services(
                    hints, {}, {}, "2026-08-07T00:00:00+00:00", None,
                )
            status.assert_called_once_with(script, raw_path=script)
            self.assertEqual(observed["heartbeat-cron"]["state"], "present")
            self.assertEqual(observed["heartbeat-cron"]["source"], "check:cron_registered+file_exists")
            self.assertEqual(
                observed["heartbeat-cron"]["checks"],
                [
                    {"kind": "file_exists", "path": script, "status": "present"},
                    {"kind": "cron_registered", "path": script, "status": "present"},
                ],
            )

            with mock.patch.object(
                nodeutils_collect, "crontab_registration_status", return_value="missing"
            ):
                observed = nodeutils_collect.normalize_observed_services(
                    hints, {}, {}, "2026-08-07T00:00:00+00:00", None,
                )
            self.assertEqual(observed["heartbeat-cron"]["state"], "missing")
            self.assertEqual(observed["heartbeat-cron"]["checks"][1]["status"], "missing")

    def test_cron_registered_check_expands_home_and_keeps_raw_needle(self) -> None:
        with mock.patch.object(
            nodeutils_collect, "crontab_registration_status", return_value="present"
        ) as status:
            observed = nodeutils_collect.normalize_observed_services(
                {
                    "service_probe_hints": {
                        "heartbeat-cron": {
                            "checks": [{"kind": "cron_registered", "path": "~/mycron/heartbeat.sh"}]
                        }
                    }
                },
                {}, {}, "2026-08-07T00:00:00+00:00", None,
            )

        expanded = str(Path("~/mycron/heartbeat.sh").expanduser())
        status.assert_called_once_with(expanded, raw_path="~/mycron/heartbeat.sh")
        self.assertEqual(observed["heartbeat-cron"]["checks"][0]["path"], expanded)

    def test_crontab_registration_status_matches_expanded_and_raw_spellings(self) -> None:
        crontab = (
            "# m h dom mon dow command\n"
            "*/10 * * * * ~/mycron/heartbeat.sh >> ~/mycron/heartbeat.log 2>&1\n"
        )
        completed = subprocess.CompletedProcess(["crontab", "-l"], 0, stdout=crontab, stderr="")
        with mock.patch.object(nodeutils_collect.shutil, "which", return_value="/usr/bin/crontab"), \
                mock.patch.object(nodeutils_collect.subprocess, "run", return_value=completed):
            self.assertEqual(
                nodeutils_collect.crontab_registration_status(
                    "/Users/eiji/mycron/heartbeat.sh", raw_path="~/mycron/heartbeat.sh"
                ),
                "present",
            )
            # A commented-out line is not a registration.
            self.assertEqual(
                nodeutils_collect.crontab_registration_status("/elsewhere/heartbeat.sh"),
                "missing",
            )

        commented = subprocess.CompletedProcess(
            ["crontab", "-l"], 0, stdout="# */10 * * * * /Users/eiji/mycron/heartbeat.sh\n", stderr=""
        )
        with mock.patch.object(nodeutils_collect.shutil, "which", return_value="/usr/bin/crontab"), \
                mock.patch.object(nodeutils_collect.subprocess, "run", return_value=commented):
            self.assertEqual(
                nodeutils_collect.crontab_registration_status("/Users/eiji/mycron/heartbeat.sh"),
                "missing",
            )

    def test_crontab_registration_status_fails_truthfully(self) -> None:
        # Empty crontab ("no crontab for user", exit 1) is proof of absence;
        # an unusable crontab tool is an error, never proof either way.
        no_crontab = subprocess.CompletedProcess(["crontab", "-l"], 1, stdout="", stderr="no crontab for eiji")
        with mock.patch.object(nodeutils_collect.shutil, "which", return_value="/usr/bin/crontab"), \
                mock.patch.object(nodeutils_collect.subprocess, "run", return_value=no_crontab):
            self.assertEqual(nodeutils_collect.crontab_registration_status("/x/y.sh"), "missing")

        denied = subprocess.CompletedProcess(["crontab", "-l"], 1, stdout="", stderr="permission denied")
        with mock.patch.object(nodeutils_collect.shutil, "which", return_value="/usr/bin/crontab"), \
                mock.patch.object(nodeutils_collect.subprocess, "run", return_value=denied):
            self.assertEqual(nodeutils_collect.crontab_registration_status("/x/y.sh"), "error")

        with mock.patch.object(nodeutils_collect.shutil, "which", return_value=None):
            self.assertEqual(nodeutils_collect.crontab_registration_status("/x/y.sh"), "error")

        with mock.patch.object(nodeutils_collect.shutil, "which", return_value="/usr/bin/crontab"), \
                mock.patch.object(
                    nodeutils_collect.subprocess, "run",
                    side_effect=subprocess.TimeoutExpired(["crontab", "-l"], 8),
                ):
            self.assertEqual(nodeutils_collect.crontab_registration_status("/x/y.sh"), "error")

    def test_cron_registered_check_does_not_override_running_detection(self) -> None:
        with mock.patch.object(
            nodeutils_collect, "crontab_registration_status", return_value="missing"
        ):
            observed = nodeutils_collect.normalize_observed_services(
                {
                    "service_probe_hints": {
                        "heartbeat-cron": {"checks": [{"kind": "cron_registered", "path": "/x/y.sh"}]}
                    }
                },
                {}, {}, "2026-08-07T00:00:00+00:00", None,
                {"important_services": [{"service": "heartbeat-cron", "process": "heartbeat", "state": "active"}]},
            )

        self.assertEqual(observed["heartbeat-cron"]["state"], "active")
        self.assertEqual(observed["heartbeat-cron"]["source"], "process")
        self.assertEqual(
            observed["heartbeat-cron"]["checks"],
            [{"kind": "cron_registered", "path": "/x/y.sh", "status": "missing"}],
        )

    def test_unanswered_http_check_leaves_no_entry(self) -> None:
        with mock.patch.object(
            nodeutils_collect, "probe_http_paths", return_value=None
        ):
            observed = nodeutils_collect.normalize_observed_services(
                {
                    "service_probe_hints": {
                        "ollama": {"endpoint": "http://127.0.0.1:9999", "checks": [{"kind": "http", "paths": ["/"]}]}
                    }
                },
                {}, {}, "2026-08-06T00:00:00+00:00", None,
            )

        self.assertNotIn("ollama", observed)

    def test_http_check_without_endpoint_hint_is_skipped(self) -> None:
        with mock.patch.object(service_endpoint_probes.urllib.request, "urlopen") as urlopen:
            observed = nodeutils_collect.normalize_observed_services(
                {"service_probe_hints": {"ollama": {"checks": [{"kind": "http", "paths": ["/"]}]}}},
                {}, {}, "2026-08-06T00:00:00+00:00", None,
            )

        self.assertNotIn("ollama", observed)
        urlopen.assert_not_called()


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

    # --- bindings (service_relation Phase 3) ---------------------------------

    def test_observe_binding_present_and_reachable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "opencode.json"
            path.write_text(json.dumps({"provider": {"ollama": {"options": {"baseURL": "http://agstudio.home.arpa:11434/v1"}}}}))
            spec = {"config_file": str(path), "json_path": "provider.ollama.options.baseURL"}

            response = mock.MagicMock()
            response.status = 200
            response.__enter__.return_value = response
            with mock.patch.object(nodeutils_collect.urllib.request, "urlopen", return_value=response) as urlopen:
                entry = nodeutils_collect.observe_binding(spec, "2026-08-01T00:00:00+00:00")

            self.assertEqual(entry["configuration_status"], "present")
            self.assertEqual(entry["configured_endpoint"], "http://agstudio.home.arpa:11434/v1")
            self.assertEqual(entry["reachability_status"], "reachable")
            self.assertEqual(entry["http_status"], 200)
            self.assertEqual(entry["checked_at"], "2026-08-01T00:00:00+00:00")
            self.assertEqual(urlopen.call_args.args[0], "http://agstudio.home.arpa:11434/v1/models")

    def test_observe_binding_unreachable_when_probe_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "opencode.json"
            path.write_text(json.dumps({"provider": {"ollama": {"options": {"baseURL": "http://dead.example:11434/v1"}}}}))
            spec = {"config_file": str(path), "json_path": "provider.ollama.options.baseURL"}

            with mock.patch.object(nodeutils_collect.urllib.request, "urlopen", side_effect=OSError("no route")):
                entry = nodeutils_collect.observe_binding(spec, "2026-08-01T00:00:00+00:00")

            self.assertEqual(entry["configuration_status"], "present")
            self.assertEqual(entry["reachability_status"], "unreachable")
            self.assertNotIn("http_status", entry)

    def test_observe_binding_absent_when_config_file_missing(self) -> None:
        spec = {"config_file": "/nonexistent/opencode.json", "json_path": "provider.ollama.options.baseURL"}

        entry = nodeutils_collect.observe_binding(spec, "2026-08-01T00:00:00+00:00")

        self.assertEqual(entry["configuration_status"], "absent")
        self.assertNotIn("configured_endpoint", entry)

    def test_observe_binding_absent_when_slot_missing_from_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "opencode.json"
            path.write_text(json.dumps({"provider": {}}))
            spec = {"config_file": str(path), "json_path": "provider.ollama.options.baseURL"}

            entry = nodeutils_collect.observe_binding(spec, "2026-08-01T00:00:00+00:00")

            self.assertEqual(entry["configuration_status"], "absent")

    def test_observe_binding_unreadable_when_json_is_malformed(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "opencode.json"
            path.write_text("{not valid json")
            spec = {"config_file": str(path), "json_path": "provider.ollama.options.baseURL"}

            entry = nodeutils_collect.observe_binding(spec, "2026-08-01T00:00:00+00:00")

            self.assertEqual(entry["configuration_status"], "unreadable")

    def test_observe_binding_expands_home_relative_config_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "opencode.json"
            path.write_text(json.dumps({"a": {"b": "http://x:1/v1"}}))
            spec = {"config_file": str(path), "json_path": "a.b"}

            with mock.patch.object(Path, "expanduser", return_value=path):
                with mock.patch.object(nodeutils_collect.urllib.request, "urlopen", side_effect=OSError()):
                    entry = nodeutils_collect.observe_binding({"config_file": "~/opencode.json", "json_path": "a.b"}, "t")

            self.assertEqual(entry["configuration_status"], "present")
            self.assertEqual(entry["configured_endpoint"], "http://x:1/v1")

    def test_no_secret_value_survives_bounded_value_in_a_binding_observation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "opencode.json"
            path.write_text(json.dumps({"a": {"b": "x" * 600}}))
            spec = {"config_file": str(path), "json_path": "a.b"}

            with mock.patch.object(nodeutils_collect.urllib.request, "urlopen", side_effect=OSError()):
                entry = nodeutils_collect.observe_binding(spec, "t")

            self.assertLessEqual(len(entry["configured_endpoint"]), nodeutils_collect.MAX_STRING_LENGTH + len("...[truncated]"))

    def test_bindings_for_service_rejects_malformed_spec(self) -> None:
        config = {"service_probe_hints": {"node-agent": {"bindings": {"llm_provider": "not-a-mapping"}}}}

        results = nodeutils_collect.bindings_for_service("node-agent", config, "2026-08-01T00:00:00+00:00")

        self.assertEqual(results, {})

    def test_normalize_observed_services_attaches_bindings_without_docker_or_systemd_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "opencode.json"
            path.write_text(json.dumps({"provider": {"ollama": {"options": {"baseURL": "http://agstudio.home.arpa:11434/v1"}}}}))
            config = {
                "service_probe_hints": {
                    "node-agent": {
                        "bindings": {
                            "llm_provider": {"config_file": str(path), "json_path": "provider.ollama.options.baseURL"},
                        },
                    },
                }
            }

            with mock.patch.object(nodeutils_collect.urllib.request, "urlopen", side_effect=OSError()):
                observed = nodeutils_collect.normalize_observed_services(
                    config, {}, {}, "2026-08-01T00:00:00+00:00", None,
                )

            self.assertIn("node-agent", observed)
            self.assertEqual(observed["node-agent"]["source"], "probe")
            self.assertEqual(observed["node-agent"]["bindings"]["llm_provider"]["configuration_status"], "present")
            self.assertEqual(observed["node-agent"]["bindings"]["llm_provider"]["reachability_status"], "unreachable")

    def test_no_file_content_ever_appears_in_a_managed_file_observation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nintent-records.conf"
            secret_line = "host-record=super-secret-hostname.example,192.0.2.10"
            path.write_text(secret_line + "\n")

            entry = nodeutils_collect.observe_managed_file(str(path), "2026-07-22T00:00:00+00:00")

            self.assertNotIn(secret_line, json.dumps(entry))


def _init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main", str(path)], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "t@example.com"], check=True)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "test"], check=True)


def _commit_all(path: Path, message: str) -> None:
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", message], check=True)


class ObserveWorkspaceTests(unittest.TestCase):
    def test_missing_path_is_present_false(self) -> None:
        entry = nodeutils_collect.observe_workspace(
            {"path": "/nonexistent/pj-example"}, "2026-08-01T00:00:00+00:00"
        )

        self.assertEqual(entry["present"], False)
        self.assertNotIn("head_sha", entry)

    def test_non_git_directory_is_present_with_no_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            entry = nodeutils_collect.observe_workspace({"path": tmpdir}, "2026-08-01T00:00:00+00:00")

        self.assertEqual(entry["present"], True)
        self.assertEqual(entry["raw"]["is_git"], False)
        self.assertNotIn("head_sha", entry)
        self.assertNotIn("remote_url", entry)

    def test_present_clean_git_repo_reports_identity_and_not_dirty(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            _init_git_repo(path)
            (path / "f.txt").write_text("hello")
            _commit_all(path, "init")

            entry = nodeutils_collect.observe_workspace({"path": str(path)}, "2026-08-01T00:00:00+00:00")

        self.assertEqual(entry["present"], True)
        self.assertEqual(entry["branch"], "main")
        self.assertEqual(entry["dirty"], False)
        self.assertIn("head_sha", entry)
        self.assertIn("last_commit_at", entry)
        self.assertNotIn("ahead", entry)
        self.assertNotIn("behind", entry)

    def test_present_dirty_and_ahead_of_upstream(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            remote = base / "remote.git"
            work = base / "work"
            subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True)
            work.mkdir()
            _init_git_repo(work)
            (work / "f.txt").write_text("hello")
            _commit_all(work, "init")
            subprocess.run(["git", "-C", str(work), "remote", "add", "origin", str(remote)], check=True)
            subprocess.run(["git", "-C", str(work), "push", "-q", "-u", "origin", "main"], check=True)
            (work / "f.txt").write_text("changed")
            _commit_all(work, "local change")
            (work / "untracked.txt").write_text("wip")

            entry = nodeutils_collect.observe_workspace({"path": str(work)}, "2026-08-01T00:00:00+00:00")

        self.assertEqual(entry["present"], True)
        self.assertEqual(entry["dirty"], True)
        self.assertEqual(entry["ahead"], 1)
        self.assertEqual(entry["behind"], 0)
        self.assertEqual(entry["remote_url"], str(remote))

    def test_individual_git_command_failure_yields_partial_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            _init_git_repo(path)
            (path / "f.txt").write_text("hello")
            _commit_all(path, "init")

            real_run_git = nodeutils_collect.run_git

            def flaky_run_git(target: Path, args: list, timeout: int = 8):
                if args[:1] == ["log"]:
                    return None
                return real_run_git(target, args, timeout=timeout)

            with mock.patch.object(nodeutils_collect, "run_git", side_effect=flaky_run_git):
                entry = nodeutils_collect.observe_workspace({"path": str(path)}, "2026-08-01T00:00:00+00:00")

        self.assertEqual(entry["present"], True)
        self.assertIn("head_sha", entry)
        self.assertNotIn("last_commit_at", entry)

    def test_workspace_probe_hints_ignores_malformed_entries(self) -> None:
        config = {"workspace_probe_hints": {"pj-example": {"path": "/x"}, "bad": "not-a-mapping"}}

        hints = nodeutils_collect.workspace_probe_hints(config)

        self.assertEqual(hints, {"pj-example": {"path": "/x"}})

    def test_get_workspace_summary_keys_by_hint_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {"workspace_probe_hints": {"pj-example": {"path": tmpdir}}}

            summary = nodeutils_collect.get_workspace_summary(config, "2026-08-01T00:00:00+00:00")

        self.assertIn("pj-example", summary)
        self.assertEqual(summary["pj-example"]["present"], True)

    def test_pj_voxel3dprint_is_no_longer_a_hardcoded_important_service(self) -> None:
        self.assertNotIn("pj-voxel3dprint", nodeutils_collect.IMPORTANT_SERVICE_NAMES)


if __name__ == "__main__":
    unittest.main()
