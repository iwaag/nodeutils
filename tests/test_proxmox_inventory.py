from __future__ import annotations

import subprocess
import unittest
from unittest import mock

import proxmox_inventory


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["x"], returncode=returncode, stdout=stdout, stderr=stderr)


class ProxmoxInventoryTests(unittest.TestCase):
    def test_get_proxmox_mode_rejects_invalid_value(self) -> None:
        with self.assertRaises(proxmox_inventory.ProxmoxInventoryError):
            proxmox_inventory.get_proxmox_mode({"proxmox": {"enabled": "sometimes"}})

    def test_auto_mode_skips_non_proxmox_host(self) -> None:
        with (
            mock.patch.object(proxmox_inventory, "is_proxmox_host", return_value=False),
            mock.patch("subprocess.run") as run_mock,
        ):
            inventory = proxmox_inventory.collect_proxmox_inventory({}, {"short_hostname": "node1"})

        self.assertEqual(
            inventory,
            {"enabled": False, "detected": False, "mode": "auto"},
        )
        run_mock.assert_not_called()

    def test_required_endpoint_failure_stops_collection(self) -> None:
        with (
            mock.patch.object(proxmox_inventory, "is_proxmox_host", return_value=True),
            mock.patch.object(proxmox_inventory.shutil, "which", return_value="/usr/bin/pvesh"),
            mock.patch.object(
                proxmox_inventory,
                "run_command",
                return_value="pve-manager/9.1.1/abc",
            ),
            mock.patch.object(
                proxmox_inventory,
                "run_pvesh",
                side_effect=proxmox_inventory.ProxmoxInventoryError("failed to run pvesh get /cluster/status"),
            ),
        ):
            with self.assertRaises(proxmox_inventory.ProxmoxInventoryError):
                proxmox_inventory.collect_proxmox_inventory({}, {"short_hostname": "node1"})


class RunPveshExecutionTests(unittest.TestCase):
    def test_root_mode_invokes_direct_pvesh_with_exact_argv(self) -> None:
        with (
            mock.patch.object(proxmox_inventory.os, "geteuid", return_value=0),
            mock.patch.object(
                proxmox_inventory.subprocess,
                "run",
                return_value=_completed(stdout='{"ok": true}'),
            ) as run_mock,
        ):
            result = proxmox_inventory.run_pvesh("/cluster/status")

        run_mock.assert_called_once_with(
            ["/usr/bin/pvesh", "get", "/cluster/status", "--output-format", "json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result, {"ok": True})

    def test_non_root_mode_invokes_only_sudo_helper(self) -> None:
        with (
            mock.patch.object(proxmox_inventory.os, "geteuid", return_value=1000),
            mock.patch.object(proxmox_inventory.Path, "is_file", return_value=True),
            mock.patch.object(proxmox_inventory.os, "access", return_value=True),
            mock.patch.object(
                proxmox_inventory.subprocess,
                "run",
                return_value=_completed(stdout='{"ok": true}'),
            ) as run_mock,
        ):
            result = proxmox_inventory.run_pvesh("/cluster/status")

        run_mock.assert_called_once_with(
            ["/usr/bin/sudo", "-n", "/usr/local/libexec/nodeutils-pvesh-read", "/cluster/status"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result, {"ok": True})

    def test_missing_helper_raises_specific_error(self) -> None:
        with (
            mock.patch.object(proxmox_inventory.os, "geteuid", return_value=1000),
            mock.patch.object(proxmox_inventory.Path, "is_file", return_value=False),
            mock.patch.object(proxmox_inventory.subprocess, "run") as run_mock,
        ):
            with self.assertRaisesRegex(proxmox_inventory.ProxmoxInventoryError, "helper unavailable"):
                proxmox_inventory.run_pvesh("/cluster/status")
        run_mock.assert_not_called()

    def test_denied_sudo_raises_specific_error(self) -> None:
        with (
            mock.patch.object(proxmox_inventory.os, "geteuid", return_value=1000),
            mock.patch.object(proxmox_inventory.Path, "is_file", return_value=True),
            mock.patch.object(proxmox_inventory.os, "access", return_value=True),
            mock.patch.object(
                proxmox_inventory.subprocess,
                "run",
                return_value=_completed(returncode=1, stderr="sudo: a password is required"),
            ),
        ):
            with self.assertRaisesRegex(proxmox_inventory.ProxmoxInventoryError, "not authorized"):
                proxmox_inventory.run_pvesh("/cluster/status")

    def test_helper_path_rejection_raises_specific_error(self) -> None:
        with (
            mock.patch.object(proxmox_inventory.os, "geteuid", return_value=1000),
            mock.patch.object(proxmox_inventory.Path, "is_file", return_value=True),
            mock.patch.object(proxmox_inventory.os, "access", return_value=True),
            mock.patch.object(
                proxmox_inventory.subprocess,
                "run",
                return_value=_completed(
                    returncode=1,
                    stderr="nodeutils-pvesh-read: rejected API path",
                ),
            ),
        ):
            with self.assertRaisesRegex(proxmox_inventory.ProxmoxInventoryError, "rejected"):
                proxmox_inventory.run_pvesh("/cluster/status")

    def test_pvesh_ipc_failure_is_distinct_from_helper_or_sudo_errors(self) -> None:
        with (
            mock.patch.object(proxmox_inventory.os, "geteuid", return_value=0),
            mock.patch.object(
                proxmox_inventory.subprocess,
                "run",
                return_value=_completed(returncode=255, stderr="ipcc_send_rec[1] failed: Unknown error -1"),
            ),
        ):
            with self.assertRaisesRegex(proxmox_inventory.ProxmoxInventoryError, r"rc=255"):
                proxmox_inventory.run_pvesh("/cluster/status")

    def test_timeout_is_distinct_error(self) -> None:
        with (
            mock.patch.object(proxmox_inventory.os, "geteuid", return_value=0),
            mock.patch.object(
                proxmox_inventory.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(cmd="pvesh", timeout=15),
            ),
        ):
            with self.assertRaisesRegex(proxmox_inventory.ProxmoxInventoryError, "timed out"):
                proxmox_inventory.run_pvesh("/cluster/status")

    def test_invalid_json_is_distinct_error(self) -> None:
        with (
            mock.patch.object(proxmox_inventory.os, "geteuid", return_value=0),
            mock.patch.object(
                proxmox_inventory.subprocess,
                "run",
                return_value=_completed(stdout="not json"),
            ),
        ):
            with self.assertRaisesRegex(proxmox_inventory.ProxmoxInventoryError, "invalid JSON"):
                proxmox_inventory.run_pvesh("/cluster/status")

    def test_error_message_does_not_leak_unbounded_stderr(self) -> None:
        huge_stderr = "x" * 5000
        with (
            mock.patch.object(proxmox_inventory.os, "geteuid", return_value=0),
            mock.patch.object(
                proxmox_inventory.subprocess,
                "run",
                return_value=_completed(returncode=1, stderr=huge_stderr),
            ),
        ):
            with self.assertRaises(proxmox_inventory.ProxmoxInventoryError) as ctx:
                proxmox_inventory.run_pvesh("/cluster/status")
        self.assertLess(len(str(ctx.exception)), 400)

    def test_normalize_qemu_vm_maps_basic_fields(self) -> None:
        raw = {
            "vmid": 101,
            "name": "app01",
            "status": "running",
            "maxcpu": 4,
            "maxmem": 4 * 1024**3,
            "maxdisk": 32 * 1024**3,
        }
        with (
            mock.patch.object(
                proxmox_inventory,
                "run_pvesh",
                return_value={"net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"},
            ),
            mock.patch.object(proxmox_inventory, "collect_guest_agent_interfaces", return_value=[]),
        ):
            vm = proxmox_inventory.normalize_qemu_vm(
                raw,
                "pve1",
                {},
                proxmox_inventory.DEFAULT_PROXMOX_CONFIG,
            )

        self.assertEqual(vm["name"], "app01")
        self.assertEqual(vm["guest_type"], "qemu")
        self.assertEqual(vm["status"], "Active")
        self.assertEqual(vm["memory_mb"], 4096)
        self.assertEqual(vm["disk_gb"], 32.0)
        self.assertEqual(vm["interfaces"][0]["bridge"], "vmbr0")

    def test_normalize_lxc_container_marks_lxc_type(self) -> None:
        raw = {
            "vmid": 202,
            "name": "ct01",
            "status": "stopped",
            "maxmem": 512 * 1024**2,
        }
        with mock.patch.object(
            proxmox_inventory,
            "run_pvesh",
            return_value={"net0": "name=eth0,hwaddr=AA:BB:CC:DD:EE:11,bridge=vmbr0,ip=dhcp", "unprivileged": 1},
        ):
            container = proxmox_inventory.normalize_lxc_container(
                raw,
                "pve1",
                {},
                proxmox_inventory.DEFAULT_PROXMOX_CONFIG,
            )

        self.assertEqual(container["guest_type"], "lxc")
        self.assertEqual(container["status"], "Offline")
        self.assertEqual(container["memory_mb"], 512)
        self.assertEqual(container["interfaces"][0]["name"], "net0")
        self.assertEqual(container["unprivileged"], 1)


if __name__ == "__main__":
    unittest.main()
