"""Service-specific HTTP endpoint probe definitions and execution."""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class HttpProbeSpec:
    """Closed HTTP probe definition for one supported service."""

    paths: tuple[str, ...]


HTTP_PROBE_SPECS: dict[str, HttpProbeSpec] = {
    "ollama": HttpProbeSpec(paths=("/v1/models", "/api/tags")),
    "swarmui": HttpProbeSpec(paths=("/",)),
    "comfyui": HttpProbeSpec(paths=("/",)),
}


def probe_service_endpoint(service_name: str, endpoint: str) -> int | None:
    """Return a bounded health status for a registered desired service API."""

    spec = HTTP_PROBE_SPECS.get(service_name)
    if spec is None:
        return None

    for path in spec.paths:
        try:
            with urllib.request.urlopen(f"{endpoint.rstrip('/')}{path}", timeout=3) as response:
                return int(response.status)
        except urllib.error.HTTPError as exc:
            return int(exc.code)
        except (OSError, ValueError):
            continue
    return None
