# Node Utilities

This repository contains scripts that run on individual hosts.

## Nautobot Self Register

`nautobot-self-register` collects local inventory from Ubuntu/Linux and macOS systems and creates or updates the current machine as a Nautobot Device.

The Nautobot-side Job and seed data live in the separate `nauto` repository. Run that Job first so the required Nautobot objects exist before hosts self-register.

Collected inventory includes OS, CPU, memory, disk, network, best-effort GPU accelerator details, and a lightweight Docker/systemd service snapshot. NVIDIA GPUs are read with `nvidia-smi` when available; Linux falls back to `lspci` for generic display/accelerator detection, and macOS uses `system_profiler SPDisplaysDataType`. Missing GPU, Docker, or systemd tools do not fail registration.

Docker collection is intentionally limited to scheduler-facing facts such as engine availability, container counts, compose projects, published ports, and important service containers like `ollama`, `vllm`, `open-webui`, `hatchet`, `nautobot`, `grafana`, `prometheus`, `postgres`, and `redis`. The script does not collect container environment variables, logs, secret contents, or bind-mounted file contents.

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

GPU detection uses host commands when present. Install `pciutils` on Linux if you want the generic `lspci` fallback:

```bash
sudo apt install pciutils
```

Docker detection uses the local `docker` CLI when present:

```bash
docker version --format json
docker ps -a --format '{{json .}}'
docker compose ls --format json
```

The user running the script must have permission to talk to the Docker socket for Docker facts to be collected. If Docker is unavailable or permission is denied, self-registration continues with `docker_engine_state` set to an unavailable state.

## Configuration

Create a local `.env` file for Nautobot API access:

```bash
cp .env.example .env
editor .env
```

`self_inventory.yaml` is optional. If no config file exists, the script registers the host with default values and locally detected inventory data.

Default values:

- Location: `Home`
- Status: `Active`
- Role: `linux-workstation` on Linux, `macos-workstation` on macOS
- Tags: `self-registered`, `home`

Create `self_inventory.yaml` only when you need local overrides:

```bash
cp example.self_inventory.yaml self_inventory.yaml
editor self_inventory.yaml
```

Use `service_roles` and `preferred_services` in `self_inventory.yaml` for host-local service placement preferences. For example, a host that should normally serve local Ollama requests can declare:

```yaml
service_roles:
  - ai-inference

preferred_services:
  ollama:
    service_role: ai-inference
    preferred: true
    endpoint: "http://pc1:11434"
    startup_policy: use_existing_first
    fallback_policy: start_new_if_capacity_available
    managed_by: systemd
```

These fields describe host-local intended placement and preferred endpoints. Live capacity, such as GPU utilization or VRAM pressure, should be checked through monitoring before dispatching work.

Cluster-level desired services, such as "ollama should exist somewhere", belong in the Nautobot-side `nauto/seed/desired_services.yaml` file. They should not be copied into every host config.

Use `service_probe_hints` only when local discovery needs help normalizing observed services:

```yaml
service_probe_hints:
  ollama:
    endpoint: "http://pc1:11434"
    healthcheck_path: /api/tags
  hatchet:
    endpoint: "http://pc1:8080"
    systemd_unit: hatchet.service
```

Self-registration promotes normalized observations to the `observed_services` Device custom field.

Provide `NAUTOBOT_URL` and `NAUTOBOT_TOKEN` via `.env` or shell environment variables. When using `.env`, load it with `uv run --env-file .env ...`. Do not store API tokens directly in `self_inventory.yaml`.

## Usage

Print collected inventory:

```bash
uv run --env-file .env nautobot-self-register --json
```

Print the planned Nautobot Device payload:

```bash
uv run --env-file .env nautobot-self-register --dry-run
```

Create or update the Nautobot Device:

```bash
uv run --env-file .env nautobot-self-register --verbose
```

Existing Devices are matched by serial number first. If no serial number is available, the script falls back to the Device name, which defaults to the local hostname.

## Scheduled Run Example

Ubuntu cron example:

```cron
0 3 * * * cd /path/to/nodeutils && uv run --env-file .env nautobot-self-register
```

Use an equivalent `launchd` schedule on macOS.
