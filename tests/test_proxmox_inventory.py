from __future__ import annotations

import unittest
from unittest import mock

import proxmox_inventory


class ProxmoxInventoryTests(unittest.TestCase):
    def test_get_proxmox_mode_rejects_invalid_value(self) -> None:
        with self.assertRaises(proxmox_inventory.ProxmoxInventoryError):
            proxmox_inventory.get_proxmox_mode({"proxmox": {"enabled": "sometimes"}})

    def test_auto_mode_skips_non_proxmox_host(self) -> None:
        with mock.patch.object(proxmox_inventory, "is_proxmox_host", return_value=False):
            inventory = proxmox_inventory.collect_proxmox_inventory({}, {"short_hostname": "node1"})

        self.assertEqual(
            inventory,
            {"enabled": False, "detected": False, "mode": "auto"},
        )

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
