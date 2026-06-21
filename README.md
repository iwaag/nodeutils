# Node Utilities

Host-side utility scripts for collecting local inventory reports.

`nodeutils` does not write to Nautobot and does not need a Nautobot API token.
It collects local facts and emits a bounded, versioned report for a central
ingestor such as the `nauto` Nautobot Job.

## Collection Scope

Collected inventory includes OS, CPU, memory, disk, network, best-effort GPU
accelerator details, Docker summary, systemd service observations, and optional
Proxmox VE inventory when running on a Proxmox host.

Docker collection is intentionally limited to scheduler-facing facts such as
engine availability, container counts, compose projects, published ports, and
important service containers like `ollama`, `vllm`, `open-webui`, `hatchet`,
`nautobot`, `grafana`, `prometheus`, `postgres`, and `redis`. The collector
does not collect environment variables, container logs, secret contents, or
bind-mounted file contents.

## Supported Hosts

- Ubuntu / Linux
- macOS
- Windows is not supported

## Dependencies

Install dependencies with `uv`:

```bash
uv sync
```

If you install dependencies directly with `pip`, install `psutil` and `PyYAML`.

GPU detection uses host commands when present. Install `pciutils` on Linux if
you want the generic `lspci` fallback:

```bash
sudo apt install pciutils
```

Proxmox detection and inventory use local Proxmox tools:

```bash
pveversion --verbose
pvesh get /cluster/status --output-format json
pvesh get /cluster/resources --output-format json
```

## Configuration

`self_inventory.yaml` is optional. It contains host-local hints only, such as
owner, purpose, service probe hints, and preferred services. It must not contain
Nautobot API credentials or authoritative Nautobot fields such as final role,
location, status, or tags.

Create a local config only when you need hints:

```bash
cp example.self_inventory.yaml self_inventory.yaml
editor self_inventory.yaml
```

Cluster-level desired services, such as "ollama should exist somewhere", belong
in the central `nauto/seed/desired_services.yaml` file. They should not be
copied into every host config.

## Usage

Print a JSON report:

```bash
uv run nodeutils collect --format json
```

Write a JSON report to disk with mode `0600`:

```bash
uv run nodeutils collect --format json --output /var/lib/nodeutils/inventory.json
```

Print YAML:

```bash
uv run nodeutils collect --format yaml
```

Force Proxmox collection and fail if this is not a usable Proxmox host:

```bash
uv run nodeutils collect --proxmox enabled --output /var/lib/nodeutils/inventory.json
```

The report has this top-level shape:

```yaml
schema_version: nodeutils.inventory.v1
collector:
  name: nodeutils
  version: 0.1.0
  command: collect
identity:
  hostname: pc1
  fqdn: pc1.example.local
  serial_number: "..."
  machine_id: "..."
collected_at: "2026-06-21T00:00:00+00:00"
facts: {}
self_reported: {}
```

The host report is self-reported evidence. The central ingestor is responsible
for validating it, matching the host, applying policy, and writing to Nautobot
with server-side credentials.

## Scheduled Run Example

Ubuntu cron example:

```cron
0 3 * * * cd /path/to/nodeutils && uv run nodeutils collect --output /var/lib/nodeutils/inventory.json
```

Use an equivalent `launchd` schedule on macOS.
