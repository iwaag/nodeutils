"""End-to-end boundary test: non-root nodeutils collector -> exact sudo helper argv ->
the real ansible_agdev nodeutils-pvesh-read helper -> allowlisted fake pvesh JSON ->
schema-v2 report written by a non-root process -> report readable by nctl's normal
retrieval path.

This is the "highest-practical integration test" required by
devdocs/small/permission_fix/plan_pvesh.md Step 5. It cannot use the real, fixed
/usr/bin/pvesh or a real sudoers grant (those only exist on aghub and are covered by the
Step 6 live verification), so it substitutes a fake pvesh and a pass-through fake sudo at
the process boundary while exercising the *real* helper source file's allowlist,
argument-count enforcement, and os.execve-based dispatch exactly as installed by
ansible_agdev/roles/nodeutils_pvesh_helper.

Requires the pj-clusterintent superproject checkout (nodeutils and ansible_agdev as
sibling directories); skipped, not failed, when run from a standalone nodeutils clone
that lacks that sibling directory.
"""

from __future__ import annotations

import json
import stat
import sys
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

import nodeutils_collect
import proxmox_inventory

_HELPER_SRC = (
    Path(__file__).resolve().parents[2]
    / "ansible_agdev"
    / "roles"
    / "nodeutils_pvesh_helper"
    / "files"
    / "nodeutils-pvesh-read"
)

_FAKE_RESPONSES = {
    "/cluster/status": [{"id": "node/aghub", "type": "node", "name": "aghub", "local": 1}],
    "/cluster/resources": [],
    "/nodes": [{"node": "aghub"}],
    "/nodes/aghub/qemu": [],
    "/nodes/aghub/lxc": [],
    "/nodes/aghub/storage": [],
    "/nodes/aghub/network": [],
}


def _write_fake_pvesh(path: Path, log_path: Path) -> None:
    script = f"""#!{sys.executable}
import json
import sys

RESPONSES = {_FAKE_RESPONSES!r}

def main():
    argv = sys.argv[1:]
    if len(argv) != 4 or argv[0] != "get" or argv[2:] != ["--output-format", "json"]:
        sys.exit("fake-pvesh: unexpected argv")
    api_path = argv[1]
    with open({str(log_path)!r}, "a", encoding="utf-8") as fh:
        fh.write("get " + api_path + chr(10))
    if api_path not in RESPONSES:
        sys.exit("fake-pvesh: unknown path " + api_path)
    print(json.dumps(RESPONSES[api_path]))

if __name__ == "__main__":
    main()
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def _write_fake_sudo(path: Path) -> None:
    script = f"""#!{sys.executable}
import os
import sys

argv = sys.argv[1:]
assert argv[0] == "-n", argv
os.execv(argv[1], argv[1:])
"""
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)


def _write_patched_helper_copy(dest: Path, fake_pvesh: Path) -> None:
    source = _HELPER_SRC.read_text(encoding="utf-8")
    assert 'PVESH_BIN = "/usr/bin/pvesh"' in source, "helper source shape changed; update this test"
    patched = source.replace(
        "#!/usr/bin/python3.13 -I", f"#!{sys.executable}"
    ).replace(
        'PVESH_BIN = "/usr/bin/pvesh"', f'PVESH_BIN = "{fake_pvesh}"'
    )
    dest.write_text(patched, encoding="utf-8")
    dest.chmod(0o755)


@unittest.skipUnless(_HELPER_SRC.is_file(), "ansible_agdev sibling checkout not available")
class PveshHelperBoundaryIntegrationTest(unittest.TestCase):
    def test_non_root_collection_through_real_helper_produces_readable_v2_report(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_pvesh = tmp_path / "fake-pvesh"
            fake_sudo = tmp_path / "fake-sudo"
            helper_copy = tmp_path / "nodeutils-pvesh-read"
            pvesh_log = tmp_path / "pvesh-calls.log"
            report_path = tmp_path / "inventory.json"
            config_path = tmp_path / "self_inventory.yaml"
            config_path.write_text("", encoding="utf-8")

            _write_fake_pvesh(fake_pvesh, pvesh_log)
            _write_fake_sudo(fake_sudo)
            _write_patched_helper_copy(helper_copy, fake_pvesh)

            with (
                mock.patch.object(proxmox_inventory.os, "geteuid", return_value=1000),
                mock.patch.object(proxmox_inventory, "SUDO_BIN", str(fake_sudo)),
                mock.patch.object(proxmox_inventory, "PVESH_HELPER_PATH", str(helper_copy)),
                mock.patch.object(proxmox_inventory, "is_proxmox_host", return_value=True),
                mock.patch.object(proxmox_inventory.shutil, "which", return_value=str(fake_pvesh)),
            ):
                rc = nodeutils_collect.main(
                    [
                        "collect",
                        "--config",
                        str(config_path),
                        "--format",
                        "json",
                        "--output",
                        str(report_path),
                        "--proxmox",
                        "enabled",
                    ]
                )

            self.assertEqual(rc, 0)

            # Positive evidence the real helper actually executed pvesh calls (a skipped
            # Proxmox path -- e.g. is_proxmox_host() short-circuiting -- would leave this
            # log empty or absent, which must not count as a pass).
            self.assertTrue(pvesh_log.exists(), "fake pvesh was never invoked")
            called_paths = pvesh_log.read_text(encoding="utf-8").splitlines()
            self.assertIn("get /cluster/status", called_paths)
            self.assertIn("get /cluster/resources", called_paths)
            self.assertIn("get /nodes", called_paths)

            # The report was written by this (non-root, in this test) process with mode 0600.
            mode = stat.S_IMODE(report_path.stat().st_mode)
            self.assertEqual(oct(mode), "0o600")

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["schema_version"], nodeutils_collect.SCHEMA_VERSION)
            proxmox_facts = report["facts"]["proxmox"]
            self.assertTrue(proxmox_facts["enabled"])
            self.assertTrue(proxmox_facts["detected"])
            self.assertEqual(proxmox_facts["cluster"]["nodes"], ["aghub"])

            # The report remains readable by the normal nctl retrieval path. nctl's own
            # virtualenv (pydantic, yaml) is not available inside nodeutils' venv, so this
            # asserts the exact required-field contract nctl_core.dumps.NodeDump enforces
            # (see nctl/src/nctl_core/dumps.py) directly against the written JSON, rather
            # than importing nctl_core cross-venv.
            self.assertEqual(report["schema_version"], "nodeutils.inventory.v2")
            self.assertIsInstance(report["identity"]["hostname"], str)
            self.assertTrue(report["identity"]["hostname"])
            self.assertIsInstance(report["collected_at"], str)
            datetime.fromisoformat(report["collected_at"])
            self.assertIsInstance(report["facts"], dict)
            self.assertIsInstance(report["self_reported"], dict)


if __name__ == "__main__":
    unittest.main()
