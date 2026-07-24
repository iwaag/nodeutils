"""Collect Proxmox VE inventory for nodeutils reports.

Emits the ``nodeutils.proxmox.v1`` nested schema described in
``devdocs/big/vm/p2/plan.md`` Section 5.2 of the pj-clusterintent superproject.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

PROXMOX_SOURCE = "nodeutils-proxmox"
PROXMOX_SCHEMA_VERSION = "nodeutils.proxmox.v1"

# Security-protocol constants shared with ansible_agdev's nodeutils_pvesh_helper role. Both sides
# must assert the exact same helper path so the sudo grant and this caller cannot drift apart.
# Confirmed root-owned on aghub in devdocs/small/permission_fix/report0.md; not configurable via
# the host-local probe YAML.
PVESH_BIN = "/usr/bin/pvesh"
PVESH_HELPER_PATH = "/usr/local/libexec/nodeutils-pvesh-read"
SUDO_BIN = "/usr/bin/sudo"

_STDERR_SNIPPET_LIMIT = 200

# Section 5.2 "Semantic collection limits".
LIMIT_NODES = 64
LIMIT_QEMU_GUESTS = 512
LIMIT_LXC_GUESTS = 512
LIMIT_CONFIG_INTERFACES_PER_GUEST = 64
LIMIT_AGENT_INTERFACES_PER_GUEST = 256
LIMIT_ADDRESSES_PER_AGENT_INTERFACE = 64
LIMIT_STORAGE_SCOPES = 128
LIMIT_VZTMPL_ITEMS_PER_STORAGE = 2048
LIMIT_ERRORS_PER_SCOPE = 128

DEFAULT_PROXMOX_CONFIG: dict[str, Any] = {
    "enabled": "auto",
    "cluster_type": "Proxmox VE",
    "cluster_status": "Active",
    "host_role": "proxmox-host",
    "host_device_type": "Proxmox Host",
    "qemu_role": "virtual-machine",
    "lxc_role": "lxc-container",
    "guest_status_map": {
        "running": "Active",
        "stopped": "Offline",
        "paused": "Offline",
    },
    "include_guest_interfaces": True,
    "include_guest_ips": True,
}

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_NET_SLOT_RE = re.compile(r"^net(\d+)$")
_ROOTFS_SIZE_RE = re.compile(r"(?:^|,)size=(\d+(?:\.\d+)?)([kKmMgGtT]?)(?:,|$)")


class ProxmoxInventoryError(RuntimeError):
    pass


def run_command(command: list[str], timeout: int = 10) -> str | None:
    if not command or shutil.which(command[0]) is None:
        return None
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def read_os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            data[key] = value.strip().strip('"')
    except OSError:
        pass
    return data


def get_proxmox_config(config: dict[str, Any]) -> dict[str, Any]:
    proxmox_config = dict(DEFAULT_PROXMOX_CONFIG)
    raw = config.get("proxmox")
    if isinstance(raw, dict):
        proxmox_config.update(raw)
        if isinstance(raw.get("guest_status_map"), dict):
            merged_status_map = dict(DEFAULT_PROXMOX_CONFIG["guest_status_map"])
            merged_status_map.update(raw["guest_status_map"])
            proxmox_config["guest_status_map"] = merged_status_map
    return proxmox_config


def get_proxmox_mode(config: dict[str, Any], cli_mode: str | None = None) -> str:
    mode = cli_mode or str(get_proxmox_config(config).get("enabled", "auto"))
    if mode not in {"auto", "enabled", "disabled"}:
        raise ProxmoxInventoryError(f"invalid Proxmox mode: {mode}")
    return mode


def is_proxmox_host() -> bool:
    if platform.system() != "Linux":
        return False
    if Path("/etc/pve").exists():
        return True
    os_release = read_os_release()
    release_text = " ".join(str(value) for value in os_release.values()).lower()
    if "proxmox" in release_text or "pve" in str(os_release.get("ID", "")).lower():
        return True
    return run_command(["pveversion"], timeout=5) is not None


def _bounded_stderr(stderr: str | None) -> str:
    text = (stderr or "").strip()
    if len(text) > _STDERR_SNIPPET_LIMIT:
        text = text[:_STDERR_SNIPPET_LIMIT] + "…"
    return text


def _pvesh_argv(path: str) -> list[str]:
    if os.geteuid() == 0:
        return [PVESH_BIN, "get", path, "--output-format", "json"]
    if not (Path(PVESH_HELPER_PATH).is_file() and os.access(PVESH_HELPER_PATH, os.X_OK)):
        raise ProxmoxInventoryError(
            f"privileged pvesh helper unavailable at {PVESH_HELPER_PATH}; "
            "install the nodeutils_pvesh_helper role before collecting Proxmox inventory"
        )
    return [SUDO_BIN, "-n", PVESH_HELPER_PATH, path]


def run_pvesh(path: str, timeout: int = 15) -> Any:
    argv = _pvesh_argv(path)

    try:
        completed = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise ProxmoxInventoryError(f"pvesh get {path} timed out after {timeout}s") from exc
    except OSError as exc:
        raise ProxmoxInventoryError(f"failed to invoke pvesh for {path}: {exc.__class__.__name__}") from exc

    if completed.returncode != 0:
        stderr = _bounded_stderr(completed.stderr)
        if "a password is required" in stderr:
            raise ProxmoxInventoryError(f"passwordless sudo not authorized for pvesh get {path}")
        if stderr.startswith("nodeutils-pvesh-read:"):
            raise ProxmoxInventoryError(f"privileged pvesh helper rejected {path}: {stderr}")
        raise ProxmoxInventoryError(f"pvesh get {path} failed (rc={completed.returncode}): {stderr}")

    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ProxmoxInventoryError(f"invalid JSON from pvesh get {path}: {exc}") from exc


def parse_pveversion(output: str | None) -> dict[str, Any]:
    if not output:
        return {}
    data: dict[str, Any] = {"raw": output}
    first_line = output.splitlines()[0].strip() if output.splitlines() else ""
    if first_line:
        data["summary"] = first_line
    match = re.search(r"pve-manager/([\w.+:-]+)", output)
    if match:
        data["pve_manager"] = match.group(1)
    return data


def list_items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        data = value.get("data")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
    return []


def first_nonempty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def bytes_to_mib(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(round(float(value) / (1024**2)))
    except (TypeError, ValueError):
        return None


def bytes_to_gb(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return round(float(value) / (1024**3), 2)
    except (TypeError, ValueError):
        return None


def normalize_status(status: Any, proxmox_config: dict[str, Any]) -> str:
    raw = str(status or "").lower()
    status_map = proxmox_config.get("guest_status_map")
    if isinstance(status_map, dict):
        mapped = status_map.get(raw)
        if mapped:
            return str(mapped)
    return "Active" if raw == "running" else "Offline"


def normalize_mac(value: Any) -> tuple[str | None, bool]:
    """Return ``(normalized_mac_or_none, is_valid)``.

    An invalid, non-empty MAC is reported as invalid rather than silently dropped or guessed.
    """
    if value in (None, ""):
        return None, True
    text = str(value).strip().lower()
    if _MAC_RE.match(text):
        return text, True
    return None, False


def _make_error(scope_kind: str, scope_id: str, section: str, code: str) -> dict[str, str]:
    return {"scope_kind": scope_kind, "scope_id": scope_id, "section": section, "code": code}


class _ErrorSink:
    """Bounded, order-preserving error collector for one platform-level report."""

    def __init__(self, limit: int = LIMIT_ERRORS_PER_SCOPE) -> None:
        self._limit = limit
        self._errors: list[dict[str, str]] = []
        self.omitted_error_count = 0

    def add(self, scope_kind: str, scope_id: str, section: str, code: str) -> None:
        if len(self._errors) < self._limit:
            self._errors.append(_make_error(scope_kind, scope_id, section, code))
        else:
            self.omitted_error_count += 1

    @property
    def errors(self) -> list[dict[str, str]]:
        return list(self._errors)


def apply_limit(
    items: list[Any],
    limit: int,
    sort_key: Any,
    sink: _ErrorSink,
    scope_kind: str,
    scope_id: str,
    section: str,
) -> tuple[list[Any], bool]:
    """Sort deterministically, keep the bounded prefix, and record truncation.

    Returns ``(kept_items, truncated)``. Truncation records the omitted count via the section's
    own bookkeeping (the caller adds it to the section state), never hides it in the generic
    200-item report bounder.
    """
    ordered = sorted(items, key=sort_key)
    if len(ordered) <= limit:
        return ordered, False
    sink.add(scope_kind, scope_id, section, "truncated_collection")
    return ordered[:limit], True


def parse_qemu_net_config(slot: str, value: str) -> dict[str, Any]:
    """Parse a QEMU ``netN`` config string such as ``virtio=AA:BB:...,bridge=vmbr0``."""
    parsed: dict[str, Any] = {"config_slot": slot, "raw": value}
    mac_raw = None
    for item in value.split(","):
        if "=" not in item:
            continue
        key, item_value = item.split("=", 1)
        key = key.strip()
        item_value = item_value.strip()
        if key in {
            "virtio",
            "e1000",
            "e1000e",
            "rtl8139",
            "vmxnet3",
            "i82551",
            "i82557b",
            "i82559er",
            "ne2k_isa",
            "ne2k_pci",
            "pcnet",
            "vmxnet3",
        }:
            mac_raw = item_value
        elif key == "bridge":
            parsed["bridge"] = item_value
        elif key == "ip":
            parsed["ip"] = item_value
        elif key == "gw":
            parsed["gateway"] = item_value
        elif key == "tag":
            parsed["tag"] = item_value
    mac, mac_valid = normalize_mac(mac_raw)
    if mac_raw and not mac_valid:
        parsed["invalid_mac_raw"] = True
    if mac:
        parsed["mac_address"] = mac
    return {key: value for key, value in parsed.items() if value not in (None, "", [], {})}


def parse_lxc_net_config(slot: str, value: str) -> dict[str, Any]:
    """Parse an LXC ``netN`` config string such as ``name=eth0,bridge=vmbr0,hwaddr=...``."""
    parsed: dict[str, Any] = {"config_slot": slot, "raw": value}
    mac_raw = None
    for item in value.split(","):
        if "=" not in item:
            continue
        key, item_value = item.split("=", 1)
        key = key.strip()
        item_value = item_value.strip()
        if key in {"hwaddr", "macaddr"}:
            mac_raw = item_value
        elif key == "bridge":
            parsed["bridge"] = item_value
        elif key == "ip":
            parsed["ip"] = item_value
        elif key == "gw":
            parsed["gateway"] = item_value
        elif key == "name":
            parsed["guest_interface_name"] = item_value
    mac, mac_valid = normalize_mac(mac_raw)
    if mac_raw and not mac_valid:
        parsed["invalid_mac_raw"] = True
    if mac:
        parsed["mac_address"] = mac
    return {key: value for key, value in parsed.items() if value not in (None, "", [], {})}


def config_interfaces(config: dict[str, Any], is_lxc: bool) -> list[dict[str, Any]]:
    interfaces = []
    for key, value in config.items():
        match = _NET_SLOT_RE.match(str(key))
        if not match or not isinstance(value, str):
            continue
        parser = parse_lxc_net_config if is_lxc else parse_qemu_net_config
        interfaces.append(parser(str(key), value))
    interfaces.sort(key=lambda item: int(_NET_SLOT_RE.match(item["config_slot"]).group(1)))
    return interfaces


def collect_guest_agent_interfaces(node: str, vmid: Any) -> tuple[list[dict[str, Any]], bool]:
    """Return ``(interfaces, succeeded)``. ``succeeded=False`` means the agent read failed,
    which is interface-section partial evidence, not proof the guest itself is absent."""
    try:
        data = run_pvesh(f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces", timeout=8)
    except ProxmoxInventoryError:
        return [], False
    interfaces = []
    for item in list_items(data.get("result") if isinstance(data, dict) else data):
        name = item.get("name")
        addresses = []
        for address in item.get("ip-addresses", []) if isinstance(item.get("ip-addresses"), list) else []:
            if not isinstance(address, dict):
                continue
            ip_address = address.get("ip-address")
            if ip_address:
                addresses.append(
                    {
                        "address": ip_address,
                        "type": address.get("ip-address-type"),
                        "prefix": address.get("prefix"),
                    }
                )
        addresses = addresses[:LIMIT_ADDRESSES_PER_AGENT_INTERFACE]
        mac, mac_valid = normalize_mac(item.get("hardware-address"))
        entry: dict[str, Any] = {"guest_interface_name": name, "source": "qemu-guest-agent"}
        if mac:
            entry["mac_address"] = mac
        elif item.get("hardware-address") and not mac_valid:
            entry["invalid_mac_raw"] = True
        if addresses:
            entry["ip_addresses"] = addresses
        interfaces.append(entry)
    interfaces = interfaces[:LIMIT_AGENT_INTERFACES_PER_GUEST]
    return interfaces, True


def join_qemu_interfaces(
    config_ifaces: list[dict[str, Any]], agent_ifaces: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Join config and agent interface evidence by one unique normalized MAC.

    A MAC used by more than one config or agent entry is not eligible for a join (ambiguous);
    such entries remain in their source collection but are excluded from ``joined_interfaces``.
    """
    config_by_mac: dict[str, list[dict[str, Any]]] = {}
    for iface in config_ifaces:
        mac = iface.get("mac_address")
        if mac:
            config_by_mac.setdefault(mac, []).append(iface)
    agent_by_mac: dict[str, list[dict[str, Any]]] = {}
    for iface in agent_ifaces:
        mac = iface.get("mac_address")
        if mac:
            agent_by_mac.setdefault(mac, []).append(iface)

    joined: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    matched_macs: set[str] = set()
    for mac, config_group in config_by_mac.items():
        agent_group = agent_by_mac.get(mac, [])
        if len(config_group) == 1 and len(agent_group) == 1:
            joined.append(
                {
                    "config_slot": config_group[0]["config_slot"],
                    "mac_address": mac,
                    "bridge": config_group[0].get("bridge"),
                    "guest_interface_name": agent_group[0].get("guest_interface_name"),
                    "ip_addresses": agent_group[0].get("ip_addresses", []),
                }
            )
            matched_macs.add(mac)
        else:
            unmatched.extend(config_group)
            unmatched.extend(agent_group)
    for mac, agent_group in agent_by_mac.items():
        if mac not in config_by_mac:
            unmatched.extend(agent_group)

    return {
        "config_interfaces": config_ifaces,
        "agent_interfaces": agent_ifaces,
        "joined_interfaces": joined,
        "unmatched": unmatched,
    }


def parse_rootfs(value: Any) -> dict[str, Any] | None:
    """Parse an LXC ``rootfs`` config string, e.g. ``local-lvm:vm-108-disk-0,size=8G``.

    Returns ``None`` when the grammar is unsupported; callers must record partial rootfs
    evidence rather than falling back to aggregate ``disk_gb``.
    """
    if not isinstance(value, str) or ":" not in value:
        return None
    storage, remainder = value.split(":", 1)
    parts = remainder.split(",")
    volume = parts[0] if parts else None
    if not storage or not volume:
        return None
    size_match = _ROOTFS_SIZE_RE.search(remainder)
    result: dict[str, Any] = {"storage": storage, "volume": volume}
    if size_match:
        raw_size = float(size_match.group(1))
        unit = size_match.group(2).lower()
        multiplier = {"": 1024**3, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}.get(unit, 1024**3)
        result["size_gb"] = round(raw_size * multiplier / (1024**3), 2)
    return result


def _section(state: str, evidence_observed_at: str | None = None) -> dict[str, Any]:
    return {"state": state, "evidence_observed_at": evidence_observed_at}


def normalize_qemu_vm(
    raw: dict[str, Any],
    node: str,
    config: dict[str, Any],
    proxmox_config: dict[str, Any],
    collected_at: str | None = None,
) -> dict[str, Any]:
    """Pure normalizer: ``config`` is the already-fetched QEMU ``pvesh`` config dict."""
    vmid = raw.get("vmid")
    config_interfaces_list = config_interfaces(config, is_lxc=False)
    agent_interfaces_list: list[dict[str, Any]] = []
    agent_ok = True
    if proxmox_config.get("include_guest_ips") and vmid is not None:
        agent_interfaces_list, agent_ok = collect_guest_agent_interfaces(node, vmid)

    interfaces = join_qemu_interfaces(config_interfaces_list, agent_interfaces_list)

    guest_state = "complete" if agent_ok else "partial"
    observation = {
        "state": guest_state,
        "last_attempted_at": collected_at,
        "evidence_observed_at": collected_at,
        "omitted_error_count": 0,
        "errors": [],
        "sections": {
            "identity": _section("complete", collected_at),
            "config": _section("complete", collected_at),
            "agent_interfaces": _section("complete" if agent_ok else "partial", collected_at if agent_ok else None),
        },
    }

    return {
        "guest_type": "qemu",
        "vmid": vmid,
        "node": node,
        "name": first_nonempty(raw.get("name"), f"vm-{vmid}" if vmid is not None else None),
        "proxmox_status": raw.get("status"),
        "status": normalize_status(raw.get("status"), proxmox_config),
        "vcpus": first_nonempty(raw.get("maxcpu"), raw.get("cpus"), config.get("cores")),
        "memory_mb": bytes_to_mib(first_nonempty(raw.get("maxmem"), raw.get("mem"))),
        "disk_gb": bytes_to_gb(first_nonempty(raw.get("maxdisk"), raw.get("disk"))),
        "observation": observation,
        "interfaces": interfaces,
    }


def normalize_lxc_container(
    raw: dict[str, Any],
    node: str,
    config: dict[str, Any],
    proxmox_config: dict[str, Any],
    collected_at: str | None = None,
) -> dict[str, Any]:
    """Pure normalizer: ``config`` is the already-fetched LXC ``pvesh`` config dict."""
    vmid = raw.get("vmid")
    interfaces_list = config_interfaces(config, is_lxc=True)
    interfaces = {
        "config_interfaces": interfaces_list,
        "agent_interfaces": [],
        "joined_interfaces": interfaces_list,
        "unmatched": [],
    }

    rootfs = parse_rootfs(config.get("rootfs"))
    rootfs_state = "complete" if rootfs is not None else "partial"

    observation = {
        "state": rootfs_state,
        "last_attempted_at": collected_at,
        "evidence_observed_at": collected_at,
        "omitted_error_count": 0,
        "errors": [],
        "sections": {
            "identity": _section("complete", collected_at),
            "config": _section("complete", collected_at),
            "rootfs": _section(rootfs_state, collected_at if rootfs is not None else None),
        },
    }

    result = {
        "guest_type": "lxc",
        "vmid": vmid,
        "node": node,
        "name": first_nonempty(raw.get("name"), f"ct-{vmid}" if vmid is not None else None),
        "proxmox_status": raw.get("status"),
        "status": normalize_status(raw.get("status"), proxmox_config),
        "vcpus": first_nonempty(raw.get("maxcpu"), raw.get("cpus"), config.get("cores")),
        "memory_mb": bytes_to_mib(first_nonempty(raw.get("maxmem"), raw.get("mem"))),
        "disk_gb": bytes_to_gb(first_nonempty(raw.get("maxdisk"), raw.get("disk"))),
        "observation": observation,
        "interfaces": interfaces,
    }
    if rootfs is not None:
        result["rootfs"] = rootfs
    return result


def get_cluster_name(cluster_status: list[dict[str, Any]], host_inventory: dict[str, Any]) -> str:
    for item in cluster_status:
        if item.get("type") == "cluster" and item.get("name"):
            return str(item["name"])
    return f"{host_inventory.get('short_hostname') or socket.gethostname()}-proxmox"


def classify_cluster_identity(
    cluster_status: list[dict[str, Any]], host_inventory: dict[str, Any]
) -> dict[str, Any]:
    for item in cluster_status:
        if item.get("type") == "cluster" and item.get("name"):
            return {
                "name": str(item["name"]),
                "name_source": "proxmox_cluster_name",
                "identity_value": str(item["name"]),
            }
    node_name = str(host_inventory.get("short_hostname") or socket.gethostname())
    return {
        "name": f"{node_name}-proxmox",
        "name_source": "standalone_node_fallback",
        "identity_value": node_name,
    }


def collect_proxmox_inventory(
    config: dict[str, Any],
    host_inventory: dict[str, Any],
    mode: str | None = None,
) -> dict[str, Any]:
    proxmox_config = get_proxmox_config(config)
    proxmox_mode = get_proxmox_mode(config, mode)
    detected = is_proxmox_host()

    if proxmox_mode == "disabled":
        return {"enabled": False, "detected": detected, "mode": proxmox_mode}
    if not detected and proxmox_mode == "auto":
        return {"enabled": False, "detected": False, "mode": proxmox_mode}
    if not detected and proxmox_mode == "enabled":
        raise ProxmoxInventoryError("Proxmox mode is enabled, but this host does not look like Proxmox VE")
    if shutil.which("pvesh") is None:
        raise ProxmoxInventoryError("pvesh is required for Proxmox inventory collection")

    collected_at = host_inventory.get("collected_at")
    sink = _ErrorSink()

    cluster_status = list_items(run_pvesh("/cluster/status"))
    identity = classify_cluster_identity(cluster_status, host_inventory)

    nodes_raw = list_items(run_pvesh("/nodes"))
    node_names_all = sorted({str(item.get("node")) for item in nodes_raw if item.get("node")})
    if not node_names_all:
        node_names_all = [str(host_inventory.get("short_hostname") or socket.gethostname())]
    node_names, nodes_truncated = apply_limit(
        node_names_all, LIMIT_NODES, lambda name: name, sink, "platform", identity["name"], "node_list"
    )

    qemu_vms: list[dict[str, Any]] = []
    lxc_containers: list[dict[str, Any]] = []
    storage_content: list[dict[str, Any]] = []
    qemu_guest_lists_sections = []
    lxc_guest_lists_sections = []
    storage_sections = []
    platform_partial = nodes_truncated

    for node in node_names:
        try:
            raw_qemu_list = list_items(run_pvesh(f"/nodes/{node}/qemu"))
            qemu_guest_lists_sections.append({"node": node, "state": "complete", "evidence_observed_at": collected_at})
        except ProxmoxInventoryError:
            raw_qemu_list = []
            qemu_guest_lists_sections.append({"node": node, "state": "partial", "evidence_observed_at": None})
            sink.add("platform", identity["name"], "qemu_guest_lists", "guest_list_failed")
            platform_partial = True

        for raw_vm in raw_qemu_list[: LIMIT_QEMU_GUESTS]:
            vmid = raw_vm.get("vmid")
            try:
                vm_config = run_pvesh(f"/nodes/{node}/qemu/{vmid}/config", timeout=10) if vmid is not None else {}
                if not isinstance(vm_config, dict):
                    vm_config = {}
            except ProxmoxInventoryError:
                vm_config = {}
                sink.add("guest", f"qemu:{node}:{vmid}", "config", "config_read_failed")
                platform_partial = True
            try:
                qemu_vms.append(
                    normalize_qemu_vm(raw_vm, node, vm_config, proxmox_config, collected_at=collected_at)
                )
            except Exception:
                sink.add("guest", f"qemu:{node}:{vmid}", "identity", "malformed_guest")
                platform_partial = True

        try:
            raw_lxc_list = list_items(run_pvesh(f"/nodes/{node}/lxc"))
            lxc_guest_lists_sections.append({"node": node, "state": "complete", "evidence_observed_at": collected_at})
        except ProxmoxInventoryError:
            raw_lxc_list = []
            lxc_guest_lists_sections.append({"node": node, "state": "partial", "evidence_observed_at": None})
            sink.add("platform", identity["name"], "lxc_guest_lists", "guest_list_failed")
            platform_partial = True

        for raw_ct in raw_lxc_list[: LIMIT_LXC_GUESTS]:
            vmid = raw_ct.get("vmid")
            try:
                ct_config = run_pvesh(f"/nodes/{node}/lxc/{vmid}/config", timeout=10) if vmid is not None else {}
                if not isinstance(ct_config, dict):
                    ct_config = {}
            except ProxmoxInventoryError:
                ct_config = {}
                sink.add("guest", f"lxc:{node}:{vmid}", "config", "config_read_failed")
                platform_partial = True
            try:
                lxc_containers.append(
                    normalize_lxc_container(raw_ct, node, ct_config, proxmox_config, collected_at=collected_at)
                )
            except Exception:
                sink.add("guest", f"lxc:{node}:{vmid}", "identity", "malformed_guest")
                platform_partial = True

        try:
            node_storages = list_items(run_pvesh(f"/nodes/{node}/storage"))
        except ProxmoxInventoryError:
            node_storages = []
        for storage in node_storages[:LIMIT_STORAGE_SCOPES]:
            storage_name = storage.get("storage")
            content_types = str(storage.get("content", ""))
            if not storage_name or "vztmpl" not in content_types:
                continue
            scope_id = f"{node}:{storage_name}:vztmpl"
            try:
                raw_content = list_items(run_pvesh(f"/nodes/{node}/storage/{storage_name}/content"))
                items = []
                for entry in raw_content:
                    if entry.get("content") != "vztmpl":
                        continue
                    volid = entry.get("volid")
                    if not volid:
                        continue
                    items.append(
                        {
                            "volid": volid,
                            "content": "vztmpl",
                            "format": entry.get("format"),
                            "size_bytes": entry.get("size"),
                        }
                    )
                items = sorted(items, key=lambda item: item["volid"])
                items_truncated = len(items) > LIMIT_VZTMPL_ITEMS_PER_STORAGE
                if items_truncated:
                    sink.add("storage", scope_id, "storage_inventory", "truncated_collection")
                items = items[:LIMIT_VZTMPL_ITEMS_PER_STORAGE]
                storage_content.append(
                    {
                        "node": node,
                        "storage": storage_name,
                        "content_type": "vztmpl",
                        "state": "partial" if items_truncated else "complete",
                        "last_attempted_at": collected_at,
                        "evidence_observed_at": collected_at,
                        "omitted_error_count": 0,
                        "errors": [],
                        "items": items,
                    }
                )
                storage_sections.append(
                    {"node": node, "storage": storage_name, "state": "complete", "evidence_observed_at": collected_at}
                )
            except ProxmoxInventoryError:
                storage_content.append(
                    {
                        "node": node,
                        "storage": storage_name,
                        "content_type": "vztmpl",
                        "state": "partial",
                        "last_attempted_at": collected_at,
                        "evidence_observed_at": None,
                        "omitted_error_count": 0,
                        "errors": [_make_error("storage", scope_id, "storage_inventory", "storage_content_failed")],
                        "items": [],
                    }
                )
                storage_sections.append({"node": node, "storage": storage_name, "state": "partial", "evidence_observed_at": None})
                platform_partial = True

    collection_state = "partial" if platform_partial else "complete"

    return {
        "schema_version": PROXMOX_SCHEMA_VERSION,
        "enabled": True,
        "detected": True,
        "mode": proxmox_mode,
        "inventory_source": PROXMOX_SOURCE,
        "observed_at": collected_at,
        "collection": {
            "state": collection_state,
            "last_attempted_at": collected_at,
            "evidence_observed_at": collected_at if collection_state == "complete" else None,
            "omitted_error_count": sink.omitted_error_count,
            "errors": sink.errors,
            "sections": {
                "cluster_identity": _section("complete", collected_at),
                "node_list": _section("partial" if nodes_truncated else "complete", collected_at),
                "qemu_guest_lists": qemu_guest_lists_sections,
                "lxc_guest_lists": lxc_guest_lists_sections,
                "storage_inventory": storage_sections,
            },
        },
        "cluster": {
            "name": identity["name"],
            "name_source": identity["name_source"],
            "identity_value": identity["identity_value"],
            "node_count": len(node_names_all),
            "observed_node_names": node_names,
        },
        "qemu_vms": qemu_vms,
        "lxc_containers": lxc_containers,
        "storage_content": storage_content,
    }
