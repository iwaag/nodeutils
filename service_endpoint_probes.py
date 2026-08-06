"""Generic bounded HTTP endpoint probing driven by rendered check hints.

autotask_intent Step 2: the paths to probe come from the service's rendered
`checks` hint (`kind: http`), owned by the deployment-profile layer in
`ansible_agdev/vars/deployment_profiles.yml`. nodeutils no longer keys probe
knowledge by service name.
"""

from __future__ import annotations

import urllib.error
import urllib.request


def probe_http_paths(endpoint: str, paths: list[str]) -> int | None:
    """Return the first bounded HTTP status for `endpoint` across `paths`."""

    for path in paths:
        try:
            with urllib.request.urlopen(f"{endpoint.rstrip('/')}{path}", timeout=3) as response:
                return int(response.status)
        except urllib.error.HTTPError as exc:
            return int(exc.code)
        except (OSError, ValueError):
            continue
    return None
