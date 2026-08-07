from __future__ import annotations

import subprocess
import unittest
from unittest import mock

import proxmox_inventory


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["x"], returncode=returncode, stdout=stdout, stderr=stderr)


COLLECTED_AT = "2026-07-24T12:00:00+00:00"


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


class MacNormalizationTests(unittest.TestCase):
    def test_valid_mac_is_lowercased(self) -> None:
        mac, valid = proxmox_inventory.normalize_mac("AA:BB:CC:DD:EE:FF")
        self.assertEqual(mac, "aa:bb:cc:dd:ee:ff")
        self.assertTrue(valid)

    def test_invalid_mac_is_reported_not_guessed(self) -> None:
        mac, valid = proxmox_inventory.normalize_mac("not-a-mac")
        self.assertIsNone(mac)
        self.assertFalse(valid)

    def test_empty_mac_is_valid_absence(self) -> None:
        mac, valid = proxmox_inventory.normalize_mac(None)
        self.assertIsNone(mac)
        self.assertTrue(valid)


class QemuInterfaceParsingTests(unittest.TestCase):
    def test_parses_model_prefixed_mac(self) -> None:
        parsed = proxmox_inventory.parse_qemu_net_config("net0", "virtio=BC:24:11:47:92:AF,bridge=vmbr0,firewall=1")
        self.assertEqual(parsed["mac_address"], "bc:24:11:47:92:af")
        self.assertEqual(parsed["bridge"], "vmbr0")
        self.assertEqual(parsed["config_slot"], "net0")

    def test_invalid_mac_recorded_not_dropped_silently(self) -> None:
        parsed = proxmox_inventory.parse_qemu_net_config("net0", "virtio=zz,bridge=vmbr0")
        self.assertNotIn("mac_address", parsed)
        self.assertTrue(parsed.get("invalid_mac_raw"))


class LxcInterfaceParsingTests(unittest.TestCase):
    def test_parses_static_config(self) -> None:
        parsed = proxmox_inventory.parse_lxc_net_config(
            "net0", "name=eth0,bridge=vmbr0,gw=192.168.0.1,hwaddr=BC:24:11:23:DC:B7,ip=192.168.0.2/24,type=veth"
        )
        self.assertEqual(parsed["mac_address"], "bc:24:11:23:dc:b7")
        self.assertEqual(parsed["ip"], "192.168.0.2/24")
        self.assertEqual(parsed["gateway"], "192.168.0.1")

    def test_dhcp_token_has_no_ip_key_value_it_cannot_parse_as_cidr(self) -> None:
        parsed = proxmox_inventory.parse_lxc_net_config("net0", "name=eth0,bridge=vmbr0,hwaddr=AA:BB:CC:DD:EE:11,ip=dhcp")
        self.assertEqual(parsed["ip"], "dhcp")


class RootfsParsingTests(unittest.TestCase):
    def test_parses_storage_volume_and_gb_size(self) -> None:
        rootfs = proxmox_inventory.parse_rootfs("local-lvm:vm-108-disk-0,size=8G")
        self.assertEqual(rootfs, {"storage": "local-lvm", "volume": "vm-108-disk-0", "size_gb": 8.0})

    def test_missing_size_yields_partial_rootfs_without_size(self) -> None:
        rootfs = proxmox_inventory.parse_rootfs("local-lvm:vm-108-disk-0")
        self.assertEqual(rootfs, {"storage": "local-lvm", "volume": "vm-108-disk-0"})

    def test_malformed_value_returns_none(self) -> None:
        self.assertIsNone(proxmox_inventory.parse_rootfs("not-a-rootfs-string"))
        self.assertIsNone(proxmox_inventory.parse_rootfs(None))


class QemuJoinTests(unittest.TestCase):
    def test_unique_mac_joins_config_and_agent(self) -> None:
        config_ifaces = [proxmox_inventory.parse_qemu_net_config("net0", "virtio=02:7b:67:47:0d:fd,bridge=vmbr0")]
        agent_ifaces = [
            {
                "guest_interface_name": "enp0s18",
                "mac_address": "02:7b:67:47:0d:fd",
                "ip_addresses": [{"address": "192.168.0.234", "type": "ipv4", "prefix": 24}],
                "source": "qemu-guest-agent",
            }
        ]
        joined = proxmox_inventory.join_qemu_interfaces(config_ifaces, agent_ifaces)
        self.assertEqual(len(joined["joined_interfaces"]), 1)
        entry = joined["joined_interfaces"][0]
        self.assertEqual(entry["config_slot"], "net0")
        self.assertEqual(entry["guest_interface_name"], "enp0s18")
        self.assertEqual(joined["unmatched"], [])

    def test_config_only_is_not_joined(self) -> None:
        config_ifaces = [proxmox_inventory.parse_qemu_net_config("net0", "virtio=aa:bb:cc:dd:ee:ff,bridge=vmbr0")]
        joined = proxmox_inventory.join_qemu_interfaces(config_ifaces, [])
        self.assertEqual(joined["joined_interfaces"], [])
        self.assertEqual(joined["config_interfaces"], config_ifaces)

    def test_agent_only_is_not_joined(self) -> None:
        agent_ifaces = [{"guest_interface_name": "eth0", "mac_address": "aa:bb:cc:dd:ee:ff", "source": "qemu-guest-agent"}]
        joined = proxmox_inventory.join_qemu_interfaces([], agent_ifaces)
        self.assertEqual(joined["joined_interfaces"], [])
        self.assertEqual(joined["agent_interfaces"], agent_ifaces)

    def test_duplicate_mac_is_ambiguous_and_unmatched(self) -> None:
        config_ifaces = [
            proxmox_inventory.parse_qemu_net_config("net0", "virtio=aa:bb:cc:dd:ee:ff,bridge=vmbr0"),
            proxmox_inventory.parse_qemu_net_config("net1", "virtio=aa:bb:cc:dd:ee:ff,bridge=vmbr1"),
        ]
        agent_ifaces = [{"guest_interface_name": "eth0", "mac_address": "aa:bb:cc:dd:ee:ff", "source": "qemu-guest-agent"}]
        joined = proxmox_inventory.join_qemu_interfaces(config_ifaces, agent_ifaces)
        self.assertEqual(joined["joined_interfaces"], [])
        self.assertEqual(len(joined["unmatched"]), 3)


class NormalizeQemuVmTests(unittest.TestCase):
    def test_normalize_qemu_vm_maps_basic_fields_and_joins_live_style_fixture(self) -> None:
        raw = {"vmid": 102, "name": "aghaos", "status": "running", "maxcpu": 2, "maxmem": 8 * 1024**3, "maxdisk": 32 * 1024**3}
        config = {"cores": 2, "net0": "virtio=02:7b:67:47:0d:fd,bridge=vmbr0"}
        with mock.patch.object(
            proxmox_inventory,
            "collect_guest_agent_interfaces",
            return_value=(
                [
                    {
                        "guest_interface_name": "enp0s18",
                        "mac_address": "02:7b:67:47:0d:fd",
                        "ip_addresses": [{"address": "192.168.0.234", "type": "ipv4", "prefix": 24}],
                        "source": "qemu-guest-agent",
                    }
                ],
                True,
            ),
        ):
            vm = proxmox_inventory.normalize_qemu_vm(
                raw, "aghub", config, proxmox_inventory.DEFAULT_PROXMOX_CONFIG, collected_at=COLLECTED_AT
            )

        self.assertEqual(vm["name"], "aghaos")
        self.assertEqual(vm["guest_type"], "qemu")
        self.assertEqual(vm["status"], "Active")
        self.assertEqual(vm["memory_mb"], 8192)
        self.assertEqual(vm["disk_gb"], 32.0)
        self.assertEqual(vm["observation"]["state"], "complete")
        self.assertEqual(len(vm["interfaces"]["joined_interfaces"]), 1)
        self.assertNotIn("disk", vm)  # QEMU root/boot disk is absent from this schema

    def test_agent_read_failure_marks_guest_partial_but_keeps_identity(self) -> None:
        raw = {"vmid": 100, "name": "infra", "status": "stopped"}
        with mock.patch.object(proxmox_inventory, "collect_guest_agent_interfaces", return_value=([], False)):
            vm = proxmox_inventory.normalize_qemu_vm(
                raw, "aghub", {}, proxmox_inventory.DEFAULT_PROXMOX_CONFIG, collected_at=COLLECTED_AT
            )
        self.assertEqual(vm["observation"]["state"], "partial")
        self.assertEqual(vm["name"], "infra")
        self.assertEqual(vm["vmid"], 100)


class NormalizeLxcContainerTests(unittest.TestCase):
    def test_normalize_lxc_container_matches_live_agdnsmasq_fixture(self) -> None:
        raw = {"vmid": 108, "name": "agdnsmasq", "status": "running", "maxmem": 512 * 1024**2}
        config = {
            "cores": 1,
            "rootfs": "local-lvm:vm-108-disk-0,size=8G",
            "net0": "name=eth0,bridge=vmbr0,firewall=1,gw=192.168.0.1,hwaddr=BC:24:11:23:DC:B7,ip=192.168.0.2/24,type=veth",
        }
        container = proxmox_inventory.normalize_lxc_container(
            raw, "aghub", config, proxmox_inventory.DEFAULT_PROXMOX_CONFIG, collected_at=COLLECTED_AT
        )

        self.assertEqual(container["guest_type"], "lxc")
        self.assertEqual(container["vmid"], 108)
        self.assertEqual(container["node"], "aghub")
        self.assertEqual(container["status"], "Active")
        self.assertEqual(container["memory_mb"], 512)
        self.assertEqual(container["rootfs"], {"storage": "local-lvm", "volume": "vm-108-disk-0", "size_gb": 8.0})
        self.assertEqual(container["observation"]["state"], "complete")
        self.assertEqual(len(container["interfaces"]["joined_interfaces"]), 1)
        self.assertEqual(container["interfaces"]["joined_interfaces"][0]["mac_address"], "bc:24:11:23:dc:b7")

    def test_missing_rootfs_grammar_yields_partial_not_fallback_to_disk_gb(self) -> None:
        raw = {"vmid": 109, "name": "ct01", "status": "stopped", "maxdisk": 8 * 1024**3}
        container = proxmox_inventory.normalize_lxc_container(
            raw, "aghub", {}, proxmox_inventory.DEFAULT_PROXMOX_CONFIG, collected_at=COLLECTED_AT
        )
        self.assertNotIn("rootfs", container)
        self.assertEqual(container["observation"]["sections"]["rootfs"]["state"], "partial")
        self.assertEqual(container["disk_gb"], 8.0)  # aggregate remains display-only, never renamed


class ClusterIdentityTests(unittest.TestCase):
    def test_provider_cluster_row_is_proxmox_cluster_name(self) -> None:
        identity = proxmox_inventory.classify_cluster_identity(
            [{"type": "cluster", "name": "prod-cluster"}], {"short_hostname": "aghub"}
        )
        self.assertEqual(identity["name_source"], "proxmox_cluster_name")
        self.assertEqual(identity["name"], "prod-cluster")
        self.assertEqual(identity["identity_value"], "prod-cluster")

    def test_no_cluster_row_is_standalone_fallback(self) -> None:
        identity = proxmox_inventory.classify_cluster_identity(
            [{"type": "node", "name": "aghub"}], {"short_hostname": "aghub"}
        )
        self.assertEqual(identity["name_source"], "standalone_node_fallback")
        self.assertEqual(identity["name"], "aghub-proxmox")
        self.assertEqual(identity["identity_value"], "aghub")


class LimitsTests(unittest.TestCase):
    def test_apply_limit_truncates_deterministically_and_records_error(self) -> None:
        sink = proxmox_inventory._ErrorSink()
        items = [f"node{i:03d}" for i in range(70)]
        kept, truncated = proxmox_inventory.apply_limit(
            items, proxmox_inventory.LIMIT_NODES, lambda v: v, sink, "platform", "aghub-proxmox", "node_list"
        )
        self.assertTrue(truncated)
        self.assertEqual(len(kept), proxmox_inventory.LIMIT_NODES)
        self.assertEqual(kept, sorted(items)[: proxmox_inventory.LIMIT_NODES])
        self.assertEqual(len(sink.errors), 1)
        self.assertEqual(sink.errors[0]["code"], "truncated_collection")

    def test_under_limit_is_not_truncated(self) -> None:
        sink = proxmox_inventory._ErrorSink()
        kept, truncated = proxmox_inventory.apply_limit(
            ["b", "a"], proxmox_inventory.LIMIT_NODES, lambda v: v, sink, "platform", "x", "node_list"
        )
        self.assertFalse(truncated)
        self.assertEqual(kept, ["a", "b"])
        self.assertEqual(sink.errors, [])

    def test_error_sink_bounds_and_counts_omitted(self) -> None:
        sink = proxmox_inventory._ErrorSink(limit=2)
        for i in range(5):
            sink.add("guest", f"lxc:aghub:{i}", "identity", "malformed_guest")
        self.assertEqual(len(sink.errors), 2)
        self.assertEqual(sink.omitted_error_count, 3)


class CollectProxmoxInventoryFixtureTests(unittest.TestCase):
    """End-to-end fixture using the live agdnsmasq (LXC 108) / aghaos (QEMU 102) shapes."""

    def _pvesh_side_effect(self, path: str, timeout: int = 15):
        responses = {
            "/cluster/status": [{"id": "node/aghub", "type": "node", "name": "aghub"}],
            "/nodes": [{"node": "aghub", "type": "node"}],
            "/nodes/aghub/qemu": [{"vmid": 102, "name": "aghaos", "status": "running"}],
            "/nodes/aghub/qemu/102/config": {
                "cores": 2,
                "net0": "virtio=02:7b:67:47:0d:fd,bridge=vmbr0",
            },
            "/nodes/aghub/lxc": [{"vmid": 108, "name": "agdnsmasq", "status": "running"}],
            "/nodes/aghub/lxc/108/config": {
                "cores": 1,
                "rootfs": "local-lvm:vm-108-disk-0,size=8G",
                "net0": "name=eth0,bridge=vmbr0,hwaddr=BC:24:11:23:DC:B7,ip=192.168.0.2/24,gw=192.168.0.1,type=veth",
            },
            "/nodes/aghub/storage": [{"storage": "local", "content": "iso,vztmpl,backup"}],
            "/nodes/aghub/storage/local/content": [
                {"volid": "local:vztmpl/debian-13-standard.tar.zst", "content": "vztmpl", "format": "tzst", "size": 123},
                {"volid": "local:iso/ubuntu-24.04.2-live-server-amd64.iso", "content": "iso", "format": "iso", "size": 456},
                {"volid": "local:backup/vzdump-lxc-108.tar.zst", "content": "backup", "format": "tar.zst", "size": 789},
            ],
        }
        if path not in responses:
            raise proxmox_inventory.ProxmoxInventoryError(f"unexpected path in fixture: {path}")
        return responses[path]

    def test_agdnsmasq_lxc_and_aghaos_qemu_positive_case(self) -> None:
        with (
            mock.patch.object(proxmox_inventory, "is_proxmox_host", return_value=True),
            mock.patch.object(proxmox_inventory.shutil, "which", return_value="/usr/bin/pvesh"),
            mock.patch.object(proxmox_inventory, "run_pvesh", side_effect=self._pvesh_side_effect),
            mock.patch.object(proxmox_inventory, "collect_guest_agent_interfaces", return_value=([], True)),
        ):
            facts = proxmox_inventory.collect_proxmox_inventory(
                {}, {"short_hostname": "aghub", "collected_at": COLLECTED_AT}
            )

        self.assertEqual(facts["schema_version"], proxmox_inventory.PROXMOX_SCHEMA_VERSION)
        self.assertEqual(facts["cluster"]["name"], "aghub-proxmox")
        self.assertEqual(facts["cluster"]["name_source"], "standalone_node_fallback")
        self.assertEqual(facts["collection"]["state"], "complete")

        lxc_by_vmid = {item["vmid"]: item for item in facts["lxc_containers"]}
        self.assertIn(108, lxc_by_vmid)
        agdnsmasq = lxc_by_vmid[108]
        self.assertEqual(agdnsmasq["name"], "agdnsmasq")
        self.assertEqual(agdnsmasq["guest_type"], "lxc")
        self.assertEqual(agdnsmasq["node"], "aghub")
        self.assertEqual(agdnsmasq["rootfs"]["volume"], "vm-108-disk-0")

        qemu_by_vmid = {item["vmid"]: item for item in facts["qemu_vms"]}
        self.assertIn(102, qemu_by_vmid)
        self.assertEqual(qemu_by_vmid[102]["name"], "aghaos")

        scopes = {(s["storage"], s["content_type"]): s for s in facts["storage_content"]}
        self.assertEqual(set(scopes), {("local", "vztmpl"), ("local", "iso")})
        vztmpl_scope = scopes[("local", "vztmpl")]
        self.assertEqual(vztmpl_scope["state"], "complete")
        self.assertEqual(vztmpl_scope["items"][0]["volid"], "local:vztmpl/debian-13-standard.tar.zst")
        iso_scope = scopes[("local", "iso")]
        self.assertEqual(iso_scope["state"], "complete")
        self.assertEqual(
            [item["volid"] for item in iso_scope["items"]],
            ["local:iso/ubuntu-24.04.2-live-server-amd64.iso"],
        )
        self.assertEqual(iso_scope["items"][0]["content"], "iso")

    def test_iso_scope_items_sorted_and_truncated(self) -> None:
        many = [
            {"volid": f"local:iso/img-{i:04d}.iso", "content": "iso", "format": "iso", "size": 1}
            for i in range(proxmox_inventory.LIMIT_CONTENT_ITEMS_PER_STORAGE + 1)
        ]

        def side_effect(path: str, timeout: int = 15):
            if path == "/nodes/aghub/storage/local/content":
                return list(reversed(many))
            return self._pvesh_side_effect(path, timeout)

        with (
            mock.patch.object(proxmox_inventory, "is_proxmox_host", return_value=True),
            mock.patch.object(proxmox_inventory.shutil, "which", return_value="/usr/bin/pvesh"),
            mock.patch.object(proxmox_inventory, "run_pvesh", side_effect=side_effect),
            mock.patch.object(proxmox_inventory, "collect_guest_agent_interfaces", return_value=([], True)),
        ):
            facts = proxmox_inventory.collect_proxmox_inventory(
                {}, {"short_hostname": "aghub", "collected_at": COLLECTED_AT}
            )

        scopes = {(s["storage"], s["content_type"]): s for s in facts["storage_content"]}
        iso_scope = scopes[("local", "iso")]
        self.assertEqual(iso_scope["state"], "partial")
        self.assertEqual(len(iso_scope["items"]), proxmox_inventory.LIMIT_CONTENT_ITEMS_PER_STORAGE)
        volids = [item["volid"] for item in iso_scope["items"]]
        self.assertEqual(volids, sorted(volids))
        # the empty vztmpl scope from the same storage stays complete and isolated
        self.assertEqual(scopes[("local", "vztmpl")]["state"], "complete")
        self.assertEqual(scopes[("local", "vztmpl")]["items"], [])

    def test_failed_storage_listing_yields_partial_scope_per_wanted_type(self) -> None:
        def side_effect(path: str, timeout: int = 15):
            if path == "/nodes/aghub/storage/local/content":
                raise proxmox_inventory.ProxmoxInventoryError("boom")
            return self._pvesh_side_effect(path, timeout)

        with (
            mock.patch.object(proxmox_inventory, "is_proxmox_host", return_value=True),
            mock.patch.object(proxmox_inventory.shutil, "which", return_value="/usr/bin/pvesh"),
            mock.patch.object(proxmox_inventory, "run_pvesh", side_effect=side_effect),
            mock.patch.object(proxmox_inventory, "collect_guest_agent_interfaces", return_value=([], True)),
        ):
            facts = proxmox_inventory.collect_proxmox_inventory(
                {}, {"short_hostname": "aghub", "collected_at": COLLECTED_AT}
            )

        self.assertEqual(facts["collection"]["state"], "partial")
        scopes = {(s["storage"], s["content_type"]): s for s in facts["storage_content"]}
        self.assertEqual(set(scopes), {("local", "vztmpl"), ("local", "iso")})
        for scope in scopes.values():
            self.assertEqual(scope["state"], "partial")
            self.assertEqual(scope["items"], [])
            self.assertEqual(scope["errors"][0]["code"], "storage_content_failed")

    def test_one_malformed_guest_isolates_and_marks_platform_partial(self) -> None:
        def side_effect(path: str, timeout: int = 15):
            if path == "/nodes/aghub/lxc/108/config":
                raise proxmox_inventory.ProxmoxInventoryError("boom")
            return self._pvesh_side_effect(path, timeout)

        with (
            mock.patch.object(proxmox_inventory, "is_proxmox_host", return_value=True),
            mock.patch.object(proxmox_inventory.shutil, "which", return_value="/usr/bin/pvesh"),
            mock.patch.object(proxmox_inventory, "run_pvesh", side_effect=side_effect),
            mock.patch.object(proxmox_inventory, "collect_guest_agent_interfaces", return_value=([], True)),
        ):
            facts = proxmox_inventory.collect_proxmox_inventory(
                {}, {"short_hostname": "aghub", "collected_at": COLLECTED_AT}
            )

        self.assertEqual(facts["collection"]["state"], "partial")
        lxc_by_vmid = {item["vmid"]: item for item in facts["lxc_containers"]}
        self.assertIn(108, lxc_by_vmid)  # guest-list identity survives a failed config read
        self.assertNotIn("rootfs", lxc_by_vmid[108])
        self.assertIn(102, {item["vmid"] for item in facts["qemu_vms"]})  # unrelated guest unaffected


if __name__ == "__main__":
    unittest.main()
