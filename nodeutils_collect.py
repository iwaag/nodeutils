#!/usr/bin/env python3
"""Collect local host inventory and emit a bounded nodeutils inventory report."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import ipaddress
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    import psutil  # type: ignore
except ImportError:  # pragma: no cover - depends on host environment
    psutil = None

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - depends on host environment
    yaml = None

import proxmox_inventory
from proxmox_inventory import ProxmoxInventoryError

SCHEMA_VERSION = "nodeutils.inventory.v1"
COLLECTOR_NAME = "nodeutils"
COLLECTOR_COMMAND = "collect"
COLLECTOR_VERSION = "0.1.0"
SELF_SOURCE = "nodeutils"
MAX_STRING_LENGTH = 512
MAX_LIST_ITEMS = 200
MAX_DICT_ITEMS = 200
MAX_REPORT_BYTES = 2 * 1024 * 1024
SUSPICIOUS_KEY_PARTS = ("token", "secret", "password", "passwd", "credential", "apikey", "api_key")
DEFAULT_CONFIG: dict[str, Any] = {
    "include_all_docker_containers": True,
}
IMPORTANT_SERVICE_NAMES = (
    "ollama",
    "vllm",
    "open-webui",
    "hatchet",
    "nautobot",
    "grafana",
    "prometheus",
    "postgres",
    "redis",
)


class InventoryError(RuntimeError):
    pass


def run_command(command: list[str], timeout: int = 8) -> str | None:
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


def read_text(path: str) -> str | None:
    try:
        text = Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return text or None


def get_machine_id() -> str | None:
    if platform.system() != "Linux":
        return None
    return first_nonempty(read_text("/etc/machine-id"), read_text("/var/lib/dbus/machine-id"))


def first_nonempty(*values: Any) -> Any:
    for value in values:
        if value not in (None, ""):
            return value
    return None


def normalize_gb(bytes_value: float | int | None) -> float | None:
    if bytes_value is None:
        return None
    return round(float(bytes_value) / (1024**3), 2)


def parse_simple_yaml(text: str) -> dict[str, Any]:
    """Small fallback parser for the example config shape.

    It supports top-level scalar keys and top-level lists. Install PyYAML for
    general YAML support.
    """
    result: dict[str, Any] = {}
    current_list_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.startswith("  - ") and current_list_key:
            result.setdefault(current_list_key, []).append(line[4:].strip().strip('"\''))
            continue
        current_list_key = None
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not value:
            result[key] = []
            current_list_key = key
            continue
        if value.lower() in {"true", "false"}:
            result[key] = value.lower() == "true"
        else:
            result[key] = value.strip('"\'')
    return result


def load_config(path: Path, missing_ok: bool = False) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        if missing_ok and not path.exists():
            return copy.deepcopy(DEFAULT_CONFIG)
        raise InventoryError(f"failed to read config: {path}: {exc}") from exc

    if path.suffix.lower() == ".json":
        loaded = json.loads(text)
    elif yaml is not None:
        loaded = yaml.safe_load(text) or {}
        if not isinstance(loaded, dict):
            raise InventoryError("config root must be a mapping")
    else:
        loaded = parse_simple_yaml(text)
    if not isinstance(loaded, dict):
        raise InventoryError("config root must be a mapping")
    config = copy.deepcopy(DEFAULT_CONFIG)
    config.update(loaded)
    return config


def get_linux_os_release() -> dict[str, str]:
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


def get_macos_system_profiler() -> dict[str, str]:
    output = run_command(["system_profiler", "SPHardwareDataType"], timeout=15)
    if not output:
        return {}
    data: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def get_cpu_model(system: str) -> str | None:
    if system == "Linux":
        cpuinfo = read_text("/proc/cpuinfo")
        if cpuinfo:
            for line in cpuinfo.splitlines():
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
        return run_command(["lscpu"])
    if system == "Darwin":
        return first_nonempty(
            run_command(["sysctl", "-n", "machdep.cpu.brand_string"]),
            run_command(["sysctl", "-n", "hw.model"]),
        )
    return platform.processor() or None


def get_linux_hardware() -> dict[str, Any]:
    return {
        "manufacturer": first_nonempty(
            read_text("/sys/class/dmi/id/sys_vendor"),
            read_text("/sys/class/dmi/id/board_vendor"),
            "Generic",
        ),
        "model": first_nonempty(
            read_text("/sys/class/dmi/id/product_name"),
            read_text("/sys/class/dmi/id/board_name"),
            "Ubuntu PC",
        ),
        "serial_number": first_nonempty(
            read_text("/sys/class/dmi/id/product_serial"),
            read_text("/sys/class/dmi/id/board_serial"),
        ),
        "product_version": read_text("/sys/class/dmi/id/product_version"),
    }


def get_macos_hardware() -> dict[str, Any]:
    profiler = get_macos_system_profiler()
    return {
        "manufacturer": "Apple",
        "model": first_nonempty(
            profiler.get("Model Name"),
            profiler.get("Model Identifier"),
            "Mac",
        ),
        "model_identifier": profiler.get("Model Identifier"),
        "serial_number": profiler.get("Serial Number (system)"),
        "chip": profiler.get("Chip"),
    }


def get_memory_gb() -> float | None:
    if psutil is not None:
        return normalize_gb(psutil.virtual_memory().total)
    if platform.system() == "Linux":
        meminfo = read_text("/proc/meminfo")
        if meminfo:
            match = re.search(r"^MemTotal:\s+(\d+)\s+kB$", meminfo, re.MULTILINE)
            if match:
                return round(int(match.group(1)) / (1024**2), 2)
    if platform.system() == "Darwin":
        output = run_command(["sysctl", "-n", "hw.memsize"])
        if output and output.isdigit():
            return normalize_gb(int(output))
    return None


def normalize_mib_to_gb(mib_value: float | int | str | None) -> float | None:
    if mib_value in (None, ""):
        return None
    try:
        return round(float(mib_value) / 1024, 2)
    except (TypeError, ValueError):
        return None


def parse_gpu_memory_gb(text: str | None) -> float | None:
    if not text:
        return None
    match = re.search(r"([\d.]+)\s*(GB|GiB|MB|MiB)", text, re.IGNORECASE)
    if not match:
        return None
    value = float(match.group(1))
    unit = match.group(2).lower()
    if unit in {"gb", "gib"}:
        return round(value, 2)
    return normalize_mib_to_gb(value)


def get_linux_nvidia_gpus() -> tuple[bool, list[dict[str, Any]]]:
    output = run_command(
        [
            "nvidia-smi",
            "--query-gpu=name,memory.total,driver_version",
            "--format=csv,noheader,nounits",
        ],
        timeout=8,
    )
    if output is None:
        return False, []

    gpus: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if not parts or not parts[0]:
            continue
        memory_gb = normalize_mib_to_gb(parts[1]) if len(parts) > 1 else None
        gpus.append(
            {
                "name": parts[0],
                "vendor": "NVIDIA",
                "memory_gb": memory_gb,
                "driver_version": parts[2] if len(parts) > 2 and parts[2] else None,
                "source": "nvidia-smi",
            }
        )
    return True, gpus


def get_linux_lspci_gpus(existing_names: set[str] | None = None) -> tuple[bool, list[dict[str, Any]]]:
    output = run_command(["lspci", "-mm"], timeout=8)
    if output is None:
        return False, []

    existing = {name.lower() for name in existing_names or set()}
    gpus: list[dict[str, Any]] = []
    gpu_classes = ("vga compatible controller", "3d controller", "display controller")
    for line in output.splitlines():
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        if len(parts) < 3:
            continue
        device_class = parts[1].lower()
        if not any(gpu_class in device_class for gpu_class in gpu_classes):
            continue
        vendor = parts[2]
        model = parts[3] if len(parts) > 3 else vendor
        name = f"{vendor} {model}".strip()
        if name.lower() in existing or model.lower() in existing:
            continue
        gpus.append(
            {
                "name": name,
                "vendor": vendor,
                "memory_gb": None,
                "source": "lspci",
            }
        )
    return True, gpus


def get_macos_gpus() -> tuple[bool, list[dict[str, Any]]]:
    output = run_command(["system_profiler", "SPDisplaysDataType"], timeout=20)
    if output is None:
        return False, []

    gpus: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        if key in {"Chipset Model", "Model"} and value:
            if current and current.get("name"):
                gpus.append(current)
            current = {
                "name": value,
                "vendor": "Apple" if value.startswith("Apple ") else None,
                "memory_gb": None,
                "source": "system_profiler",
            }
            continue
        if current is None:
            continue
        if key == "Vendor" and value:
            current["vendor"] = value
        elif key.startswith("VRAM") and value:
            current["memory"] = value
            current["memory_gb"] = parse_gpu_memory_gb(value)
        elif key == "Metal Support" and value:
            current["metal_support"] = value

    if current and current.get("name"):
        gpus.append(current)
    return True, gpus


def summarize_gpus(gpus: list[dict[str, Any]], detected: bool) -> dict[str, Any]:
    models = [str(gpu.get("name")) for gpu in gpus if gpu.get("name")]
    memory_values = [gpu.get("memory_gb") for gpu in gpus if isinstance(gpu.get("memory_gb"), (int, float))]
    total_memory_gb = round(sum(float(value) for value in memory_values), 2) if memory_values else None

    summary_fields = {
        "count": len(gpus) if detected else None,
        "models": ", ".join(models) if models else None,
        "memory_gb": total_memory_gb,
    }
    accelerator_summary = "; ".join(
        f"{key}={value}" for key, value in summary_fields.items() if value not in (None, "")
    )
    return {
        "detected": detected,
        "gpus": gpus,
        "count": summary_fields["count"],
        "models": summary_fields["models"],
        "memory_gb": total_memory_gb,
        "accelerator_summary": accelerator_summary or None,
    }


def get_gpu_summary(system: str) -> dict[str, Any]:
    detected = False
    gpus: list[dict[str, Any]] = []

    if system == "Linux":
        nvidia_detected, nvidia_gpus = get_linux_nvidia_gpus()
        detected = detected or nvidia_detected
        gpus.extend(nvidia_gpus)

        existing_names = {str(gpu.get("name")) for gpu in gpus if gpu.get("name")}
        lspci_detected, lspci_gpus = get_linux_lspci_gpus(existing_names)
        detected = detected or lspci_detected
        if nvidia_gpus:
            lspci_gpus = [
                gpu
                for gpu in lspci_gpus
                if "nvidia" not in f"{gpu.get('vendor', '')} {gpu.get('name', '')}".lower()
            ]
        gpus.extend(lspci_gpus)
    elif system == "Darwin":
        detected, gpus = get_macos_gpus()

    return summarize_gpus(gpus, detected)


def get_disk_summary() -> dict[str, Any]:
    total = used = free = None
    try:
        usage = shutil.disk_usage("/")
        total = normalize_gb(usage.total)
        used = normalize_gb(usage.used)
        free = normalize_gb(usage.free)
    except OSError:
        pass

    disks: list[dict[str, Any]] = []
    if platform.system() == "Linux":
        output = run_command(["lsblk", "-b", "-J", "-o", "NAME,TYPE,SIZE,MODEL,SERIAL,MOUNTPOINT"])
        if output:
            try:
                for item in json.loads(output).get("blockdevices", []):
                    if item.get("type") == "disk":
                        disks.append(
                            {
                                "name": item.get("name"),
                                "size_gb": normalize_gb(item.get("size")),
                                "model": item.get("model"),
                                "serial": item.get("serial"),
                            }
                        )
            except (TypeError, json.JSONDecodeError):
                pass
    elif platform.system() == "Darwin":
        output = run_command(["diskutil", "list", "-plist"])
        if output:
            disks.append({"summary": "diskutil plist available"})

    return {
        "root_total_gb": total,
        "root_used_gb": used,
        "root_free_gb": free,
        "disks": disks,
    }


def get_default_route_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def is_ignored_interface(name: str) -> bool:
    ignored_prefixes = (
        "lo",
        "docker",
        "br-",
        "veth",
        "virbr",
        "utun",
        "awdl",
        "llw",
        "bridge",
        "gif",
        "stf",
    )
    return name.startswith(ignored_prefixes)


def get_interfaces() -> list[dict[str, Any]]:
    interfaces: list[dict[str, Any]] = []
    if psutil is None:
        return get_interfaces_without_psutil()

    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name, addr_list in addrs.items():
        mac = None
        ipv4: list[str] = []
        ipv6: list[str] = []
        for addr in addr_list:
            family = addr.family
            if getattr(socket, "AF_LINK", None) == family or getattr(psutil, "AF_LINK", None) == family:
                if addr.address and addr.address != "00:00:00:00:00:00":
                    mac = addr.address
            elif family == socket.AF_INET and addr.address:
                if not ipaddress.ip_address(addr.address).is_loopback:
                    ipv4.append(addr.address)
            elif family == socket.AF_INET6 and addr.address:
                ip = addr.address.split("%", 1)[0]
                parsed = ipaddress.ip_address(ip)
                if not parsed.is_loopback and not parsed.is_link_local:
                    ipv6.append(ip)
        stat = stats.get(name)
        interfaces.append(
            {
                "name": name,
                "mac_address": mac,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "is_up": bool(stat.isup) if stat else None,
                "speed_mbps": stat.speed if stat and stat.speed > 0 else None,
                "ignored": is_ignored_interface(name),
            }
        )
    return interfaces


def get_interfaces_without_psutil() -> list[dict[str, Any]]:
    if platform.system() != "Linux":
        return []
    output = run_command(["ip", "-j", "addr", "show"])
    if not output:
        return []
    interfaces: list[dict[str, Any]] = []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    for item in data:
        name = item.get("ifname")
        if not name:
            continue
        ipv4: list[str] = []
        ipv6: list[str] = []
        for addr in item.get("addr_info", []):
            family = addr.get("family")
            local = addr.get("local")
            if not local:
                continue
            try:
                parsed = ipaddress.ip_address(local)
            except ValueError:
                continue
            if parsed.is_loopback:
                continue
            if family == "inet":
                ipv4.append(local)
            elif family == "inet6" and not parsed.is_link_local:
                ipv6.append(local)
        interfaces.append(
            {
                "name": name,
                "mac_address": item.get("address"),
                "ipv4": ipv4,
                "ipv6": ipv6,
                "is_up": "UP" in item.get("flags", []),
                "speed_mbps": None,
                "ignored": is_ignored_interface(name),
            }
        )
    return interfaces


def choose_primary_interface(interfaces: list[dict[str, Any]], primary_ip: str | None) -> dict[str, Any] | None:
    if not interfaces:
        return None
    if primary_ip:
        for interface in interfaces:
            if primary_ip in interface.get("ipv4", []):
                return interface
    candidates = [
        interface
        for interface in interfaces
        if interface.get("is_up") and not interface.get("ignored") and interface.get("ipv4")
    ]
    return candidates[0] if candidates else None


def get_package_summary(system: str) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "python_version": platform.python_version(),
        "docker_installed": shutil.which("docker") is not None,
    }
    if system == "Linux":
        summary["apt_installed"] = shutil.which("apt") is not None
        output = run_command(["sh", "-c", "dpkg-query -f '${binary:Package}\\n' -W 2>/dev/null | wc -l"])
        if output and output.isdigit():
            summary["apt_package_count"] = int(output)
    elif system == "Darwin":
        brew = shutil.which("brew")
        summary["brew_installed"] = brew is not None
        if brew:
            summary["brew_prefix"] = run_command(["brew", "--prefix"])
            output = run_command(["brew", "list", "--formula"])
            if output is not None:
                summary["brew_formula_count"] = len([line for line in output.splitlines() if line.strip()])
    return summary


def list_value(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list | tuple | set):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)]


def is_suspicious_key(key: Any) -> bool:
    lowered = str(key).lower()
    return any(part in lowered for part in SUSPICIOUS_KEY_PARTS)


def bounded_value(value: Any) -> Any:
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            return value[:MAX_STRING_LENGTH] + "...[truncated]"
        return value
    if isinstance(value, int | float | bool) or value is None:
        return value
    if isinstance(value, list | tuple | set):
        return [bounded_value(item) for item in list(value)[:MAX_LIST_ITEMS]]
    if isinstance(value, dict):
        bounded: dict[str, Any] = {}
        for key, item_value in list(value.items())[:MAX_DICT_ITEMS]:
            if is_suspicious_key(key):
                bounded[str(key)] = "[redacted]"
            else:
                bounded[str(key)] = bounded_value(item_value)
        return bounded
    return bounded_value(str(value))


def compact_dict(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, "", [], {})}


def parse_docker_json_lines(output: str | None) -> list[dict[str, Any]]:
    if not output:
        return []
    items: list[dict[str, Any]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            items.append(item)
    return items


def parse_docker_compose_ls(output: str | None) -> list[dict[str, Any]]:
    if not output:
        return []
    try:
        loaded = json.loads(output)
    except json.JSONDecodeError:
        return parse_docker_json_lines(output)
    if isinstance(loaded, list):
        return [item for item in loaded if isinstance(item, dict)]
    if isinstance(loaded, dict):
        return [loaded]
    return []


def parse_docker_labels(raw_labels: Any) -> dict[str, str]:
    if isinstance(raw_labels, dict):
        return {str(key): str(value) for key, value in raw_labels.items() if value not in (None, "")}
    if not isinstance(raw_labels, str) or not raw_labels.strip():
        return {}
    labels: dict[str, str] = {}
    for item in raw_labels.split(","):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        if key:
            labels[key] = value.strip()
    return labels


def docker_json_field(item: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return item[key]
    return None


def normalize_docker_ports(raw_ports: Any) -> list[str]:
    if raw_ports in (None, ""):
        return []
    if isinstance(raw_ports, list):
        return sorted({str(port) for port in raw_ports if port not in (None, "")})
    text = str(raw_ports)
    ports: set[str] = set()
    for match in re.finditer(r"(?:(?:0\.0\.0\.0|127\.0\.0\.1|\[::\]|::):)?(\d+)->(\d+)/(tcp|udp)", text):
        ports.add(f"{match.group(1)}->{match.group(2)}/{match.group(3)}")
    if not ports:
        for match in re.finditer(r"\b(\d+)/(tcp|udp)\b", text):
            ports.add(f"{match.group(1)}/{match.group(2)}")
    return sorted(ports)


def important_service_name(container: dict[str, Any]) -> str | None:
    labels = container.get("labels") if isinstance(container.get("labels"), dict) else {}
    haystack = " ".join(
        str(value or "").lower()
        for value in (
            container.get("name"),
            container.get("image"),
            labels.get("com.docker.compose.service"),
            labels.get("com.docker.compose.project"),
        )
    )
    for service_name in IMPORTANT_SERVICE_NAMES:
        if service_name in haystack:
            return service_name
    return None


def service_probe_hints(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    hints = config.get("service_probe_hints")
    if not isinstance(hints, dict):
        return {}
    return {
        str(name): value
        for name, value in hints.items()
        if name not in (None, "") and isinstance(value, dict)
    }


def endpoint_from_hint_or_port(
    service_name: str,
    config: dict[str, Any],
    ports: list[str] | None,
    primary_ip: str | None,
) -> str | None:
    hints = service_probe_hints(config)
    hint = hints.get(service_name, {})
    endpoint = hint.get("endpoint")
    if endpoint:
        return str(endpoint)

    preferred_services = config.get("preferred_services")
    if isinstance(preferred_services, dict):
        preferred = preferred_services.get(service_name)
        if isinstance(preferred, dict) and preferred.get("endpoint"):
            return str(preferred["endpoint"])

    if not primary_ip:
        return None
    for port in ports or []:
        match = re.match(r"(\d+)->\d+/(tcp|udp)$", str(port))
        if match and match.group(2) == "tcp":
            return f"http://{primary_ip}:{match.group(1)}"
    return None


def get_docker_summary(config: dict[str, Any], collected_at: str) -> dict[str, Any]:
    installed = shutil.which("docker") is not None
    summary: dict[str, Any] = {
        "installed": installed,
        "engine_state": "not_installed" if not installed else "unknown",
        "container_running_count": None,
        "container_total_count": None,
        "compose_projects": [],
        "published_ports": [],
        "important_services": [],
        "updated_at": collected_at,
    }
    if not installed:
        return summary

    version_output = run_command(["docker", "version", "--format", "json"], timeout=5)
    if version_output:
        summary["engine_state"] = "available"
        try:
            version_data = json.loads(version_output)
        except json.JSONDecodeError:
            version_data = {}
        if isinstance(version_data, dict):
            server = version_data.get("Server") if isinstance(version_data.get("Server"), dict) else {}
            summary["server_version"] = server.get("Version") or version_data.get("ServerVersion")
    else:
        summary["engine_state"] = "unavailable"
        return summary

    containers: list[dict[str, Any]] = []
    ps_output = run_command(["docker", "ps", "-a", "--format", "{{json .}}"], timeout=8)
    for item in parse_docker_json_lines(ps_output):
        labels = parse_docker_labels(docker_json_field(item, "Labels", "labels"))
        name = docker_json_field(item, "Names", "Name", "names")
        image = docker_json_field(item, "Image", "Repository", "image")
        state = docker_json_field(item, "State", "Status", "state")
        ports = normalize_docker_ports(docker_json_field(item, "Ports", "ports"))
        container = {
            "id": docker_json_field(item, "ID", "ContainerID", "id"),
            "name": name,
            "image": image,
            "state": state,
            "status": docker_json_field(item, "Status", "status"),
            "ports": ports,
            "compose_project": labels.get("com.docker.compose.project"),
            "compose_service": labels.get("com.docker.compose.service"),
            "created_at": docker_json_field(item, "CreatedAt", "Created", "created_at"),
            "labels": {
                key: value
                for key, value in labels.items()
                if key in {"com.docker.compose.project", "com.docker.compose.service"}
            },
        }
        containers.append({key: value for key, value in container.items() if value not in (None, "", [], {})})

    compose_projects: set[str] = {
        str(container["compose_project"]) for container in containers if container.get("compose_project")
    }
    compose_output = run_command(["docker", "compose", "ls", "--format", "json"], timeout=8)
    for project in parse_docker_compose_ls(compose_output):
        name = docker_json_field(project, "Name", "name")
        if name:
            compose_projects.add(str(name))

    important_services = []
    for container in containers:
        detected_name = important_service_name(container)
        if not detected_name:
            continue
        important_services.append(
            {
                "service": detected_name,
                "name": container.get("name"),
                "image": container.get("image"),
                "state": container.get("state"),
                "ports": container.get("ports", []),
                "compose_project": container.get("compose_project"),
                "compose_service": container.get("compose_service"),
            }
        )

    published_ports = sorted({port for container in containers for port in container.get("ports", [])})
    running_count = sum(1 for container in containers if str(container.get("state", "")).lower() == "running")

    summary.update(
        {
            "container_running_count": running_count,
            "container_total_count": len(containers),
            "compose_projects": sorted(compose_projects),
            "published_ports": published_ports,
            "important_services": important_services,
            "containers": containers,
        }
    )

    if config.get("include_all_docker_containers") is False:
        summary.pop("containers", None)
    return summary


def parse_systemd_units(output: str | None) -> list[dict[str, Any]]:
    if not output:
        return []
    units = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        units.append(
            {
                "unit": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": parts[4] if len(parts) > 4 else None,
            }
        )
    return units


def important_service_name_from_systemd(unit: dict[str, Any], config: dict[str, Any]) -> str | None:
    haystack = f"{unit.get('unit', '')} {unit.get('description', '')}".lower()
    for service_name in sorted(set(IMPORTANT_SERVICE_NAMES) | set(service_probe_hints(config))):
        if service_name.lower() in haystack:
            return service_name
        hint = service_probe_hints(config).get(service_name, {})
        systemd_unit = hint.get("systemd_unit")
        if systemd_unit and str(systemd_unit).lower() == str(unit.get("unit", "")).lower():
            return service_name
    return None


def get_systemd_summary(config: dict[str, Any], collected_at: str) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "available": False,
        "important_services": [],
        "updated_at": collected_at,
    }
    if platform.system() != "Linux" or shutil.which("systemctl") is None:
        return summary

    output = run_command(
        ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager"],
        timeout=5,
    )
    if output is None:
        return summary

    summary["available"] = True
    important_services = []
    for unit in parse_systemd_units(output):
        service_name = important_service_name_from_systemd(unit, config)
        if not service_name:
            continue
        important_services.append(
            {
                "service": service_name,
                "unit": unit.get("unit"),
                "state": "active" if unit.get("active") == "active" else unit.get("active"),
                "sub_state": unit.get("sub"),
                "description": unit.get("description"),
            }
        )
    summary["important_services"] = important_services
    return summary


def normalize_observed_services(
    config: dict[str, Any],
    docker: dict[str, Any],
    systemd: dict[str, Any],
    collected_at: str,
    primary_ip: str | None,
) -> dict[str, Any]:
    observed: dict[str, Any] = {}

    for item in docker.get("important_services", []) if isinstance(docker.get("important_services"), list) else []:
        if not isinstance(item, dict):
            continue
        service_name = item.get("service")
        if not service_name:
            continue
        name = str(service_name)
        ports = item.get("ports") if isinstance(item.get("ports"), list) else []
        observed[name] = {
            "state": item.get("state"),
            "source": "docker",
            "endpoint": endpoint_from_hint_or_port(name, config, ports, primary_ip),
            "ports": ports,
            "container_name": item.get("name"),
            "image": item.get("image"),
            "compose_project": item.get("compose_project"),
            "compose_service": item.get("compose_service"),
            "checked_at": collected_at,
        }

    for item in systemd.get("important_services", []) if isinstance(systemd.get("important_services"), list) else []:
        if not isinstance(item, dict):
            continue
        service_name = item.get("service")
        if not service_name:
            continue
        name = str(service_name)
        existing = observed.get(name, {})
        if existing and str(existing.get("state", "")).lower() == "running":
            continue
        observed[name] = {
            **existing,
            "state": item.get("state"),
            "source": "systemd",
            "endpoint": endpoint_from_hint_or_port(name, config, [], primary_ip),
            "unit": item.get("unit"),
            "sub_state": item.get("sub_state"),
            "checked_at": collected_at,
        }

    return {
        service_name: {key: value for key, value in data.items() if value not in (None, "", [], {})}
        for service_name, data in sorted(observed.items())
    }


def get_service_summary(config: dict[str, Any], collected_at: str, primary_ip: str | None) -> dict[str, Any]:
    service_roles = list_value(config.get("service_roles"))
    preferred_services = config.get("preferred_services") if isinstance(config.get("preferred_services"), dict) else {}
    docker = get_docker_summary(config, collected_at)
    systemd = get_systemd_summary(config, collected_at)
    observed_services = normalize_observed_services(config, docker, systemd, collected_at, primary_ip)
    return {
        "service_roles": service_roles,
        "preferred_services": preferred_services,
        "docker": docker,
        "systemd": systemd,
        "observed_services": observed_services,
    }


def make_docker_service_summary(services: dict[str, Any]) -> str | None:
    docker = services.get("docker") if isinstance(services.get("docker"), dict) else {}
    if not docker:
        return None
    important = docker.get("important_services") if isinstance(docker.get("important_services"), list) else []
    service_bits = []
    for item in important:
        if not isinstance(item, dict):
            continue
        name = first_nonempty(item.get("service"), item.get("name"))
        state = item.get("state")
        ports = ",".join(item.get("ports") or [])
        bit = str(name)
        if state:
            bit = f"{bit}:{state}"
        if ports:
            bit = f"{bit}@{ports}"
        service_bits.append(bit)

    fields = {
        "engine": docker.get("engine_state"),
        "containers": f"{docker.get('container_running_count')}/{docker.get('container_total_count')}"
        if docker.get("container_running_count") is not None and docker.get("container_total_count") is not None
        else None,
        "compose": ",".join(docker.get("compose_projects") or []),
        "ports": ",".join(docker.get("published_ports") or []),
        "important": ",".join(service_bits),
    }
    return "; ".join(f"{key}={value}" for key, value in fields.items() if value not in (None, ""))


def collect_inventory(config: dict[str, Any]) -> dict[str, Any]:
    system = platform.system()
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    hostname = socket.gethostname()
    fqdn = socket.getfqdn()

    if system == "Linux":
        os_release = get_linux_os_release()
        os_name = first_nonempty(os_release.get("PRETTY_NAME"), os_release.get("NAME"), "Linux")
        os_version = first_nonempty(os_release.get("VERSION_ID"), platform.release())
        hardware = get_linux_hardware()
    elif system == "Darwin":
        os_name = "macOS"
        os_version = first_nonempty(run_command(["sw_vers", "-productVersion"]), platform.mac_ver()[0])
        hardware = get_macos_hardware()
    else:
        raise InventoryError(f"unsupported OS: {system}")

    primary_ip = get_default_route_ip()
    interfaces = get_interfaces()
    primary_interface = choose_primary_interface(interfaces, primary_ip)
    disk_summary = get_disk_summary()
    gpu_summary = get_gpu_summary(system)
    service_summary = get_service_summary(config, now, primary_ip)

    cpu_physical = psutil.cpu_count(logical=False) if psutil is not None else None
    cpu_logical = psutil.cpu_count(logical=True) if psutil is not None else os.cpu_count()
    uptime_seconds = int(time.time() - psutil.boot_time()) if psutil is not None else None

    inventory = {
        "collected_at": now,
        "inventory_source": SELF_SOURCE,
        "system": system,
        "hostname": hostname,
        "fqdn": fqdn,
        "short_hostname": hostname.split(".", 1)[0],
        "os_name": os_name,
        "os_version": os_version,
        "kernel_version": platform.release(),
        "architecture": platform.machine(),
        "timezone": time.tzname[0] if time.tzname else None,
        "uptime_seconds": uptime_seconds,
        "hardware": hardware,
        "manufacturer": hardware.get("manufacturer"),
        "model": hardware.get("model"),
        "serial_number": hardware.get("serial_number"),
        "cpu_model": get_cpu_model(system),
        "cpu_physical_cores": cpu_physical,
        "cpu_logical_cores": cpu_logical,
        "memory_gb": get_memory_gb(),
        "gpu": gpu_summary,
        "gpu_count": gpu_summary.get("count"),
        "gpu_models": gpu_summary.get("models"),
        "gpu_memory_gb": gpu_summary.get("memory_gb"),
        "gpu_accelerator_summary": gpu_summary.get("accelerator_summary"),
        "disk": disk_summary,
        "disk_total_gb": disk_summary.get("root_total_gb"),
        "interfaces": interfaces,
        "primary_interface": primary_interface,
        "primary_ip_address": primary_ip,
        "primary_mac_address": primary_interface.get("mac_address") if primary_interface else None,
        "software": get_package_summary(system),
        "services": service_summary,
        "service_roles": service_summary.get("service_roles"),
        "preferred_services": service_summary.get("preferred_services"),
        "docker": service_summary.get("docker"),
        "systemd": service_summary.get("systemd"),
        "observed_services": service_summary.get("observed_services"),
        "docker_service_summary": make_docker_service_summary(service_summary),
        "self_reported": {
            "owner": config.get("owner"),
            "purpose": config.get("purpose"),
            "description": config.get("description"),
            "service_roles": service_summary.get("service_roles"),
            "preferred_services": service_summary.get("preferred_services"),
        },
    }
    return inventory



def build_inventory_report(config: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    facts = {
        "system": inventory.get("system"),
        "os_name": inventory.get("os_name"),
        "os_version": inventory.get("os_version"),
        "kernel_version": inventory.get("kernel_version"),
        "architecture": inventory.get("architecture"),
        "timezone": inventory.get("timezone"),
        "uptime_seconds": inventory.get("uptime_seconds"),
        "hardware": inventory.get("hardware"),
        "cpu": compact_dict(
            {
                "model": inventory.get("cpu_model"),
                "physical_cores": inventory.get("cpu_physical_cores"),
                "logical_cores": inventory.get("cpu_logical_cores"),
            }
        ),
        "memory": compact_dict({"total_gb": inventory.get("memory_gb")}),
        "disk": inventory.get("disk"),
        "network": compact_dict(
            {
                "interfaces": inventory.get("interfaces"),
                "primary_interface": inventory.get("primary_interface"),
                "primary_ip_address": inventory.get("primary_ip_address"),
                "primary_mac_address": inventory.get("primary_mac_address"),
            }
        ),
        "gpu": inventory.get("gpu"),
        "software": inventory.get("software"),
        "services": inventory.get("services"),
        "proxmox": inventory.get("proxmox"),
    }
    report = {
        "schema_version": SCHEMA_VERSION,
        "collector": {
            "name": COLLECTOR_NAME,
            "version": COLLECTOR_VERSION,
            "command": COLLECTOR_COMMAND,
        },
        "identity": compact_dict(
            {
                "hostname": inventory.get("hostname"),
                "fqdn": inventory.get("fqdn"),
                "serial_number": inventory.get("serial_number"),
                "machine_id": get_machine_id(),
            }
        ),
        "collected_at": inventory.get("collected_at"),
        "facts": compact_dict(facts),
        "self_reported": compact_dict(
            {
                "owner": config.get("owner"),
                "purpose": config.get("purpose"),
                "description": config.get("description"),
                "service_roles": list_value(config.get("service_roles")),
                "preferred_services": config.get("preferred_services")
                if isinstance(config.get("preferred_services"), dict)
                else {},
            }
        ),
    }
    return bounded_value(report)


def serialize_report(report: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output_format == "yaml":
        if yaml is None:
            raise InventoryError("YAML output requires PyYAML")
        return yaml.safe_dump(report, sort_keys=True, allow_unicode=True)
    raise InventoryError(f"unsupported output format: {output_format}")


def enforce_report_size(serialized: str) -> None:
    size = len(serialized.encode("utf-8"))
    if size > MAX_REPORT_BYTES:
        raise InventoryError(f"report is too large: {size} bytes > {MAX_REPORT_BYTES} bytes")


def write_output(output_path: Path | None, serialized: str) -> None:
    enforce_report_size(serialized)
    if output_path is None:
        print(serialized, end="")
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(output_path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(serialized)
    os.chmod(output_path, 0o600)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect_parser = subparsers.add_parser("collect", help="collect local inventory and emit a report")
    collect_parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="optional config file path; defaults to self_inventory.yaml when it exists",
    )
    collect_parser.add_argument(
        "--format",
        choices=["json", "yaml"],
        default="json",
        help="report output format",
    )
    collect_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="write report to this path with mode 0600 instead of stdout",
    )
    collect_parser.add_argument(
        "--proxmox",
        choices=["auto", "enabled", "disabled"],
        default=None,
        help="Proxmox inventory mode; defaults to config proxmox.enabled or auto",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        config_path = args.config or Path("self_inventory.yaml")
        config = load_config(config_path, missing_ok=args.config is None)
        inventory = collect_inventory(config)
        proxmox_data = proxmox_inventory.collect_proxmox_inventory(config, inventory, args.proxmox)
        if proxmox_data.get("enabled") or proxmox_data.get("detected"):
            inventory["proxmox"] = proxmox_data
        report = build_inventory_report(config, inventory)
        serialized = serialize_report(report, args.format)
        write_output(args.output, serialized)
        return 0
    except InventoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ProxmoxInventoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
