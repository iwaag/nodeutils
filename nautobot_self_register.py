#!/usr/bin/env python3
"""Collect local host inventory and upsert this machine as a Nautobot Device."""

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
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
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


DEFAULT_TIMEOUT = 15
SELF_SOURCE = "nautobot-self-register"
DEFAULT_CONFIG: dict[str, Any] = {
    "token_env": "NAUTOBOT_TOKEN",
    "api_version": "",
    "location": "Home",
    "status": "Active",
    "tags": ["self-registered", "home"],
}
DEFAULT_ROLE_BY_SYSTEM = {
    "Linux": "linux-workstation",
    "Darwin": "macos-workstation",
}
IMPORTANT_SERVICE_NAMES = (
    "ollama",
    "vllm",
    "open-webui",
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


def get_service_summary(config: dict[str, Any], collected_at: str) -> dict[str, Any]:
    service_roles = list_value(config.get("service_roles"))
    preferred_services = config.get("preferred_services") if isinstance(config.get("preferred_services"), dict) else {}
    docker = get_docker_summary(config, collected_at)
    return {
        "service_roles": service_roles,
        "preferred_services": preferred_services,
        "docker": docker,
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
        default_device_type = "Ubuntu PC"
    elif system == "Darwin":
        os_name = "macOS"
        os_version = first_nonempty(run_command(["sw_vers", "-productVersion"]), platform.mac_ver()[0])
        hardware = get_macos_hardware()
        default_device_type = "Mac"
    else:
        raise InventoryError(f"unsupported OS: {system}")

    primary_ip = get_default_route_ip()
    interfaces = get_interfaces()
    primary_interface = choose_primary_interface(interfaces, primary_ip)
    disk_summary = get_disk_summary()
    gpu_summary = get_gpu_summary(system)
    service_summary = get_service_summary(config, now)

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
        "device_type": config.get("device_type") or default_device_type,
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
        "docker_service_summary": make_docker_service_summary(service_summary),
        "self_reported": {
            "owner": config.get("owner"),
            "purpose": config.get("purpose"),
            "location": config.get("location"),
            "description": config.get("description"),
        },
    }
    return inventory


@dataclass
class NautobotClient:
    base_url: str
    token: str
    timeout: int = DEFAULT_TIMEOUT
    verify_tls: bool = True
    api_version: str | None = None

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query, doseq=True)}"
        data = None
        accept = "application/json"
        if self.api_version:
            accept = f"{accept}; version={self.api_version}"
        headers = {
            "Accept": accept,
            "Authorization": f"Token {self.token}",
        }
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise InventoryError(f"Nautobot API {method} {path} failed: HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise InventoryError(f"Nautobot API {method} {path} failed: {exc}") from exc

        if not body:
            return None
        return json.loads(body)

    def get(self, path: str, query: dict[str, Any] | None = None) -> Any:
        return self.request("GET", path, query=query)

    def post(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("POST", path, payload=payload)

    def patch(self, path: str, payload: dict[str, Any]) -> Any:
        return self.request("PATCH", path, payload=payload)


def api_results(response: Any) -> list[dict[str, Any]]:
    if isinstance(response, dict) and isinstance(response.get("results"), list):
        return response["results"]
    if isinstance(response, list):
        return response
    return []


def first_api_result(response: Any) -> dict[str, Any] | None:
    results = api_results(response)
    return results[0] if results else None


def lookup_by_name(client: NautobotClient, path: str, name: str) -> dict[str, Any] | None:
    response = client.get(path, {"name": name})
    return first_api_result(response)


def lookup_by_name_or_slug(client: NautobotClient, path: str, value: str) -> dict[str, Any] | None:
    for query_key in ("name", "slug"):
        response = client.get(path, {query_key: value})
        found = first_api_result(response)
        if found:
            return found
    return None


def lookup_status(client: NautobotClient, name: str) -> dict[str, Any] | None:
    for query_key in ("name", "label"):
        found = first_api_result(client.get("/api/extras/statuses/", {query_key: name}))
        if found:
            return found
    return None


def lookup_role(client: NautobotClient, name: str) -> dict[str, Any] | None:
    return lookup_by_name(client, "/api/extras/roles/", name)


def lookup_device_type(client: NautobotClient, value: str) -> dict[str, Any] | None:
    for query_key in ("model", "slug"):
        found = first_api_result(client.get("/api/dcim/device-types/", {query_key: value}))
        if found:
            return found
    return None


def get_token(config: dict[str, Any]) -> str:
    token_env = config.get("token_env", "NAUTOBOT_TOKEN")
    token = os.environ.get(str(token_env)) if token_env else None
    token = token or config.get("token")
    if not token:
        raise InventoryError(f"Nautobot token is required; set {token_env} or config token")
    return str(token)


def get_nautobot_url(config: dict[str, Any]) -> str:
    url = os.environ.get("NAUTOBOT_URL") or config.get("nautobot_url")
    if not url:
        raise InventoryError("Nautobot URL is required; set NAUTOBOT_URL or config nautobot_url")
    return str(url)


def require_config(config: dict[str, Any], key: str) -> str:
    value = config.get(key)
    if not value:
        raise InventoryError(f"config value is required: {key}")
    return str(value)


def get_role_name(config: dict[str, Any], inventory: dict[str, Any]) -> str:
    role = config.get("role")
    if role:
        return str(role)
    system = str(inventory.get("system") or "")
    default_role = DEFAULT_ROLE_BY_SYSTEM.get(system)
    if not default_role:
        raise InventoryError(f"no default role is defined for OS: {system}")
    return default_role


def make_ai_resource_summary(config: dict[str, Any], inventory: dict[str, Any]) -> str:
    preferred_services = (
        inventory.get("preferred_services") if isinstance(inventory.get("preferred_services"), dict) else {}
    )
    preferred_bits = []
    for service_name, service_data in sorted(preferred_services.items()):
        if not isinstance(service_data, dict):
            continue
        endpoint = service_data.get("endpoint")
        preferred_bits.append(f"{service_name}:{endpoint}" if endpoint else str(service_name))

    fields = {
        "host": config.get("device_name") or inventory.get("hostname"),
        "os": f"{inventory.get('os_name')} {inventory.get('os_version')}".strip(),
        "arch": inventory.get("architecture"),
        "cpu": inventory.get("cpu_model"),
        "cores": inventory.get("cpu_logical_cores"),
        "memory_gb": inventory.get("memory_gb"),
        "gpu": inventory.get("gpu_accelerator_summary"),
        "disk_gb": inventory.get("disk_total_gb"),
        "role": get_role_name(config, inventory),
        "location": config.get("location"),
        "purpose": config.get("purpose"),
        "ip": inventory.get("primary_ip_address"),
        "services": ",".join(list_value(inventory.get("service_roles"))),
        "preferred": ",".join(preferred_bits),
        "docker": inventory.get("docker_service_summary"),
    }
    return "; ".join(f"{key}={value}" for key, value in fields.items() if value not in (None, ""))


def make_custom_fields(config: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    raw = {
        "hostname": inventory.get("hostname"),
        "fqdn": inventory.get("fqdn"),
        "hardware": inventory.get("hardware"),
        "gpu": inventory.get("gpu"),
        "disk": inventory.get("disk"),
        "primary_interface": inventory.get("primary_interface"),
        "software": inventory.get("software"),
        "services": inventory.get("services"),
    }
    docker = inventory.get("docker") if isinstance(inventory.get("docker"), dict) else {}
    fields = {
        "owner": config.get("owner"),
        "purpose": config.get("purpose"),
        "last_seen": inventory.get("collected_at"),
        "os_name": inventory.get("os_name"),
        "os_version": inventory.get("os_version"),
        "kernel_version": inventory.get("kernel_version"),
        "architecture": inventory.get("architecture"),
        "cpu_model": inventory.get("cpu_model"),
        "cpu_cores": inventory.get("cpu_logical_cores"),
        "memory_gb": str(inventory["memory_gb"]) if inventory.get("memory_gb") is not None else None,
        "gpu_count": inventory.get("gpu_count"),
        "gpu_models": inventory.get("gpu_models"),
        "gpu_memory_gb": str(inventory["gpu_memory_gb"]) if inventory.get("gpu_memory_gb") is not None else None,
        "gpu_accelerator_summary": inventory.get("gpu_accelerator_summary"),
        "disk_total_gb": str(inventory["disk_total_gb"]) if inventory.get("disk_total_gb") is not None else None,
        "serial_number": inventory.get("serial_number"),
        "primary_mac_address": inventory.get("primary_mac_address"),
        "primary_ip_address": inventory.get("primary_ip_address"),
        "inventory_source": inventory.get("inventory_source"),
        "ai_resource_summary": make_ai_resource_summary(config, inventory),
        "agent_task_state": config.get("agent_task_state"),
        "service_roles": ", ".join(list_value(inventory.get("service_roles"))),
        "preferred_services": inventory.get("preferred_services"),
        "docker_engine_state": docker.get("engine_state"),
        "docker_container_running_count": docker.get("container_running_count"),
        "docker_container_total_count": docker.get("container_total_count"),
        "docker_compose_projects": ", ".join(docker.get("compose_projects") or []),
        "docker_published_ports": ", ".join(docker.get("published_ports") or []),
        "docker_service_summary": inventory.get("docker_service_summary"),
        "service_inventory_updated_at": docker.get("updated_at"),
        "inventory_raw_json": raw,
    }
    extra = config.get("custom_fields")
    if isinstance(extra, dict):
        fields.update(extra)
    return {key: value for key, value in fields.items() if value not in (None, "")}


def object_ref(item: dict[str, Any]) -> dict[str, Any] | int:
    return item.get("id") or item.get("url") or item


def resolve_required_objects(
    client: NautobotClient,
    config: dict[str, Any],
    inventory: dict[str, Any],
) -> dict[str, Any]:
    location = lookup_by_name_or_slug(client, "/api/dcim/locations/", require_config(config, "location"))
    role_name = get_role_name(config, inventory)
    role = lookup_role(client, role_name)
    status = lookup_status(client, require_config(config, "status"))

    manufacturer_name = str(config.get("manufacturer") or inventory.get("manufacturer") or "Generic")
    manufacturer = lookup_by_name(client, "/api/dcim/manufacturers/", manufacturer_name)
    if not manufacturer and manufacturer_name != "Generic":
        manufacturer = lookup_by_name(client, "/api/dcim/manufacturers/", "Generic")

    device_type_name = str(config.get("device_type") or inventory.get("device_type"))
    device_type = lookup_device_type(client, device_type_name)
    tags = []
    for tag_name in config.get("tags") or []:
        tag = lookup_by_name(client, "/api/extras/tags/", str(tag_name))
        if not tag:
            raise InventoryError(f"missing Nautobot tag: {tag_name}. Create it first or remove it from config.")
        tags.append(tag)

    missing = [
        name
        for name, value in {
            "location": location,
            "role": role,
            "status": status,
            "manufacturer": manufacturer,
            "device_type": device_type,
        }.items()
        if not value
    ]
    if missing:
        raise InventoryError(
            "missing Nautobot objects: "
            + ", ".join(missing)
            + ". Create them in Nautobot first or adjust the config."
        )
    return {
        "location": location,
        "role": role,
        "role_name": role_name,
        "status": status,
        "manufacturer": manufacturer,
        "device_type": device_type,
        "tags": tags,
    }


def build_device_payload(
    config: dict[str, Any],
    inventory: dict[str, Any],
    refs: dict[str, Any],
) -> dict[str, Any]:
    description = config.get("description") or f"{inventory.get('os_name')} {inventory.get('os_version')}"
    payload: dict[str, Any] = {
        "name": config.get("device_name") or inventory["hostname"],
        "device_type": object_ref(refs["device_type"]),
        "role": object_ref(refs["role"]),
        "status": object_ref(refs["status"]),
        "serial": inventory.get("serial_number") or "",
        "custom_fields": make_custom_fields(config, inventory),
        "comments": f"Managed by {SELF_SOURCE}.",
    }
    payload["location"] = object_ref(refs["location"])
    if description:
        payload["description"] = str(description)
    if refs.get("tags"):
        payload["tags"] = [object_ref(tag) for tag in refs["tags"]]
    return payload


def find_existing_device(
    client: NautobotClient,
    config: dict[str, Any],
    inventory: dict[str, Any],
) -> dict[str, Any] | None:
    serial = inventory.get("serial_number")
    if serial:
        found = first_api_result(client.get("/api/dcim/devices/", {"serial": serial}))
        if found:
            return found

    name = str(config.get("device_name") or inventory["hostname"])
    return first_api_result(client.get("/api/dcim/devices/", {"name": name}))


def upsert_device(config: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    client = NautobotClient(
        base_url=get_nautobot_url(config),
        token=get_token(config),
        timeout=int(config.get("timeout", DEFAULT_TIMEOUT)),
        api_version=str(config["api_version"]) if config.get("api_version") else None,
    )
    refs = resolve_required_objects(client, config, inventory)
    payload = build_device_payload(config, inventory, refs)
    existing = find_existing_device(client, config, inventory)
    if existing:
        result = client.patch(f"/api/dcim/devices/{existing['id']}/", payload)
        return {"action": "updated", "device": result, "payload": payload}
    result = client.post("/api/dcim/devices/", payload)
    return {"action": "created", "device": result, "payload": payload}


def build_dry_run_payload(config: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": config.get("device_name") or inventory["hostname"],
        "location": config.get("location"),
        "role": get_role_name(config, inventory),
        "status": config.get("status"),
        "manufacturer": config.get("manufacturer") or inventory.get("manufacturer") or "Generic",
        "device_type": config.get("device_type") or inventory.get("device_type"),
        "serial": inventory.get("serial_number") or "",
        "description": config.get("description"),
        "tags": config.get("tags") or [],
        "custom_fields": make_custom_fields(config, inventory),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="optional config file path; defaults to self_inventory.yaml when it exists",
    )
    parser.add_argument("--dry-run", action="store_true", help="print intended Nautobot payload only")
    parser.add_argument("--json", action="store_true", help="print collected inventory JSON")
    parser.add_argument("--verbose", action="store_true", help="print extra progress to stderr")
    parser.add_argument("--no-ipam", action="store_true", help="reserved for Phase 2; currently no-op")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        config_path = args.config or Path("self_inventory.yaml")
        config = load_config(config_path, missing_ok=args.config is None)
        inventory = collect_inventory(config)
        if args.json:
            print(json.dumps(inventory, ensure_ascii=False, indent=2, sort_keys=True))
            if not args.dry_run:
                return 0
        if args.dry_run:
            print(json.dumps(build_dry_run_payload(config, inventory), ensure_ascii=False, indent=2, sort_keys=True))
            return 0
        result = upsert_device(config, inventory)
        if args.verbose:
            print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True), file=sys.stderr)
        print(f"{result['action']}: {result['device'].get('name', inventory['hostname'])}")
        return 0
    except InventoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
