"""Collect Proxmox VE inventory for nodeutils reports."""

from __future__ import annotations

import json
import platform
import re
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

PROXMOX_SOURCE = "nodeutils-proxmox"
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


def run_pvesh(path: str, timeout: int = 15) -> Any:
    output = run_command(["pvesh", "get", path, "--output-format", "json"], timeout=timeout)
    if output is None:
        raise ProxmoxInventoryError(f"failed to run pvesh get {path}")
    try:
        return json.loads(output)
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


def parse_net_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, str):
        return {}
    parsed: dict[str, Any] = {"raw": value}
    for item in value.split(","):
        if "=" not in item:
            continue
        key, item_value = item.split("=", 1)
        parsed[key.strip()] = item_value.strip()
    return parsed


def config_interfaces(config: dict[str, Any]) -> list[dict[str, Any]]:
    interfaces = []
    for key, value in sorted(config.items()):
        if not re.match(r"^(net|eth)\d+$", str(key)):
            continue
        parsed = parse_net_config(value)
        interfaces.append(
            {
                "name": str(key),
                "mac_address": first_nonempty(parsed.get("hwaddr"), parsed.get("macaddr")),
                "bridge": parsed.get("bridge"),
                "model": parsed.get("model"),
                "tag": parsed.get("tag"),
                "ip": parsed.get("ip"),
                "gateway": parsed.get("gw"),
                "raw": parsed.get("raw"),
            }
        )
    return [{key: value for key, value in item.items() if value not in (None, "", [], {})} for item in interfaces]


def collect_guest_agent_interfaces(node: str, vmid: Any) -> list[dict[str, Any]]:
    try:
        data = run_pvesh(f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces", timeout=8)
    except ProxmoxInventoryError:
        return []
    interfaces = []
    for item in list_items(data.get("result") if isinstance(data, dict) else data):
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
        interfaces.append(
            {
                "name": item.get("name"),
                "mac_address": item.get("hardware-address"),
                "ip_addresses": addresses,
                "source": "qemu-guest-agent",
            }
        )
    return [{key: value for key, value in item.items() if value not in (None, "", [], {})} for item in interfaces]


def normalize_qemu_vm(
    raw: dict[str, Any],
    node: str,
    config: dict[str, Any],
    proxmox_config: dict[str, Any],
) -> dict[str, Any]:
    vmid = raw.get("vmid")
    details = dict(raw)
    try:
        vm_config = run_pvesh(f"/nodes/{node}/qemu/{vmid}/config", timeout=10) if vmid is not None else {}
    except ProxmoxInventoryError:
        vm_config = {}
    if isinstance(vm_config, dict):
        details.update({f"config_{key}": value for key, value in vm_config.items()})

    interfaces = config_interfaces(vm_config if isinstance(vm_config, dict) else {})
    if proxmox_config.get("include_guest_ips"):
        agent_interfaces = collect_guest_agent_interfaces(node, vmid) if vmid is not None else []
        if agent_interfaces:
            interfaces = agent_interfaces
    config_cores = vm_config.get("cores") if isinstance(vm_config, dict) else None
    config_template = vm_config.get("template") if isinstance(vm_config, dict) else None
    config_tags = vm_config.get("tags") if isinstance(vm_config, dict) else None

    return {
        "name": first_nonempty(raw.get("name"), f"vm-{vmid}" if vmid is not None else None),
        "vmid": vmid,
        "node": node,
        "guest_type": "qemu",
        "status": normalize_status(raw.get("status"), proxmox_config),
        "proxmox_status": raw.get("status"),
        "vcpus": first_nonempty(raw.get("maxcpu"), raw.get("cpus"), config_cores),
        "memory_mb": bytes_to_mib(first_nonempty(raw.get("maxmem"), raw.get("mem"))),
        "disk_gb": bytes_to_gb(first_nonempty(raw.get("maxdisk"), raw.get("disk"))),
        "template": bool(first_nonempty(raw.get("template"), config_template)),
        "tags": first_nonempty(raw.get("tags"), config_tags),
        "interfaces": interfaces,
        "raw": {key: value for key, value in details.items() if value not in (None, "")},
    }


def normalize_lxc_container(
    raw: dict[str, Any],
    node: str,
    config: dict[str, Any],
    proxmox_config: dict[str, Any],
) -> dict[str, Any]:
    vmid = raw.get("vmid")
    details = dict(raw)
    try:
        ct_config = run_pvesh(f"/nodes/{node}/lxc/{vmid}/config", timeout=10) if vmid is not None else {}
    except ProxmoxInventoryError:
        ct_config = {}
    if isinstance(ct_config, dict):
        details.update({f"config_{key}": value for key, value in ct_config.items()})
    config_cores = ct_config.get("cores") if isinstance(ct_config, dict) else None
    config_template = ct_config.get("template") if isinstance(ct_config, dict) else None
    config_tags = ct_config.get("tags") if isinstance(ct_config, dict) else None

    return {
        "name": first_nonempty(raw.get("name"), f"ct-{vmid}" if vmid is not None else None),
        "vmid": vmid,
        "node": node,
        "guest_type": "lxc",
        "status": normalize_status(raw.get("status"), proxmox_config),
        "proxmox_status": raw.get("status"),
        "vcpus": first_nonempty(raw.get("maxcpu"), raw.get("cpus"), config_cores),
        "memory_mb": bytes_to_mib(first_nonempty(raw.get("maxmem"), raw.get("mem"))),
        "disk_gb": bytes_to_gb(first_nonempty(raw.get("maxdisk"), raw.get("disk"))),
        "template": bool(first_nonempty(raw.get("template"), config_template)),
        "unprivileged": ct_config.get("unprivileged") if isinstance(ct_config, dict) else None,
        "tags": first_nonempty(raw.get("tags"), config_tags),
        "interfaces": config_interfaces(ct_config if isinstance(ct_config, dict) else {}),
        "raw": {key: value for key, value in details.items() if value not in (None, "")},
    }


def get_cluster_name(cluster_status: list[dict[str, Any]], host_inventory: dict[str, Any]) -> str:
    for item in cluster_status:
        if item.get("type") == "cluster" and item.get("name"):
            return str(item["name"])
    return f"{host_inventory.get('short_hostname') or socket.gethostname()}-proxmox"


def get_cluster_id(cluster_status: list[dict[str, Any]]) -> str | None:
    for item in cluster_status:
        if item.get("type") == "cluster":
            return item.get("id")
    return None


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

    pveversion = parse_pveversion(run_command(["pveversion", "--verbose"], timeout=10))
    cluster_status = list_items(run_pvesh("/cluster/status"))
    resources = list_items(run_pvesh("/cluster/resources"))
    nodes = list_items(run_pvesh("/nodes"))

    node_names = sorted({str(item.get("node")) for item in nodes if item.get("node")})
    if not node_names:
        node_names = sorted({str(item.get("node")) for item in resources if item.get("node")})
    if not node_names:
        node_names = [str(host_inventory.get("short_hostname") or socket.gethostname())]

    qemu_vms: list[dict[str, Any]] = []
    lxc_containers: list[dict[str, Any]] = []
    storages: list[dict[str, Any]] = []
    networks: list[dict[str, Any]] = []

    for node in node_names:
        for raw_vm in list_items(run_pvesh(f"/nodes/{node}/qemu")):
            qemu_vms.append(normalize_qemu_vm(raw_vm, node, config, proxmox_config))
        for raw_ct in list_items(run_pvesh(f"/nodes/{node}/lxc")):
            lxc_containers.append(normalize_lxc_container(raw_ct, node, config, proxmox_config))
        try:
            for storage in list_items(run_pvesh(f"/nodes/{node}/storage")):
                storage["node"] = node
                storages.append(storage)
        except ProxmoxInventoryError:
            pass
        try:
            for network in list_items(run_pvesh(f"/nodes/{node}/network")):
                network["node"] = node
                networks.append(network)
        except ProxmoxInventoryError:
            pass

    cluster_name = get_cluster_name(cluster_status, host_inventory)
    cluster_id = get_cluster_id(cluster_status)

    return {
        "enabled": True,
        "detected": True,
        "mode": proxmox_mode,
        "inventory_source": PROXMOX_SOURCE,
        "version": pveversion,
        "cluster": {
            "name": cluster_name,
            "id": cluster_id,
            "type": proxmox_config.get("cluster_type"),
            "status": proxmox_config.get("cluster_status"),
            "node_count": len(node_names),
            "nodes": node_names,
            "raw_status": cluster_status,
        },
        "nodes": nodes,
        "resources": resources,
        "qemu_vms": qemu_vms,
        "lxc_containers": lxc_containers,
        "storages": storages,
        "networks": networks,
        "summary": {
            "cluster_name": cluster_name,
            "cluster_id": cluster_id,
            "node_count": len(node_names),
            "qemu_vm_count": len(qemu_vms),
            "lxc_container_count": len(lxc_containers),
        },
    }
