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

`pvesh` requires root to reach Proxmox's `pmxcfs` IPC socket. When `nodeutils collect` runs as a
non-root user (the supported `nctl`/Ansible collection path), it does not sudo into `pvesh`
directly. Instead it requires a pre-installed, allowlisted read-only proxy:

```text
/usr/local/libexec/nodeutils-pvesh-read
```

and a matching `NOPASSWD` sudoers grant scoped to exactly that helper path (installed by the
`nodeutils_pvesh_helper` Ansible role in `ansible_agdev`; see
`devdocs/small/permission_fix/plan_pvesh.md` in the `pj-clusterintent` superproject). If the
helper is missing, `nodeutils collect` fails with a specific privileged-helper error rather than
falling back to unprivileged `pvesh` or silently skipping Proxmox collection. Running
`nodeutils collect` as root (manual/administrative use) bypasses the helper and calls `pvesh`
directly.

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
schema_version: nodeutils.inventory.v2
collector:
  name: nodeutils
  version: 0.2.0
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

### Managed-file digest observation (v2)

A service configured with `service_probe_hints.<name>.managed_files` in
`self_inventory.yaml` gets a closed content observation attached to its
`facts.services.observed_services.<name>` entry:

```json
"observed_services": {
  "dnsmasq": {
    "state": "active",
    "source": "systemd",
    "managed_files": {
      "records": {
        "path": "/etc/dnsmasq.d/nintent-records.conf",
        "status": "present",
        "sha256": "<64 lowercase hex>",
        "size": 1234,
        "checked_at": "2026-07-22T00:00:00+00:00"
      }
    }
  }
}
```

Statuses are `present`, `missing`, `unreadable`, and `too_large`. Only
absolute paths are ever probed; a relative or malformed `managed_files.*.path`
is silently dropped from the report, never resolved against the collector's
own working directory. Reads are bounded (4 MiB) and binary -- file content
never appears in the report, only metadata. This is a coordinated breaking
change from `nodeutils.inventory.v1`: there is no dual v1/v2 reader anywhere
in the pipeline, so nctl's dump parser and the nauto ingest policy must be
updated in the same maintenance window as this collector.

For dnsmasq this probes only the nctl-owned records/ranges file. It reports the
actual host digest, not a controller-side "applied" acknowledgment, and it
never serializes the file content. The checked-in `tests/fixtures/dnsmasq-v5-golden.conf`
is shared byte-for-byte with nctl's fixture; both projects independently verify
its SHA-256 (`c25e51c4efce07281e580dcfb1ecad73d666a70310f87cd28ad448241215e592`).

## Scheduled Run Example

Ubuntu cron example:

```cron
0 3 * * * cd /path/to/nodeutils && uv run nodeutils collect --output /var/lib/nodeutils/inventory.json
```

Use an equivalent `launchd` schedule on macOS.

## Tests

Run the ordinary suite with `uv run pytest -q --durations=20`. The repository
[test strategy command matrix](../README_DEV.md#test-strategy-command-matrix) defines the
privileged-helper integration gate, prerequisites, and cleanup ownership.
