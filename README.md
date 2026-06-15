# Node Utilities

This repository contains scripts that run on individual hosts.

## Nautobot Self Register

`nautobot-self-register` collects local inventory from Ubuntu/Linux and macOS systems and creates or updates the current machine as a Nautobot Device.

The Nautobot-side Job and seed data live in the separate `nauto` repository. Run that Job first so the required Nautobot objects exist before hosts self-register.

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
