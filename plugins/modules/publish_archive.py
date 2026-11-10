# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Create deterministic public AIA/CDP publish archives on the managed host."""

from __future__ import annotations

DOCUMENTATION = r"""
module: publish_archive
short_description: Create deterministic public AIA/CDP publish archives on the managed
  host
version_added: 0.1.0
description:
- Create deterministic public AIA/CDP publish archives on the managed host.
- Authority-derived archives include certificates and CRLs for every retained issuer
  generation. Legacy unsuffixed URLs keep their original issuer; subsequent generations
  receive distinct filenames. Current signing certificates remain in C(ca/).
- Generate CRLs with M(jomrr.ca.crl) before publishing. Missing active-generation
  artifacts cause failure. For retired generations, retain public certificates
  and include their final CRL if it exists; no private key is required.
- Explicit O(artifacts) remain literal. With this override the caller must include
  every generation at the URLs embedded in its certificates; do not publish the
  current CA certificate at a legacy URL belonging to an older key.
requirements:
- cryptography >= 43 on the managed host when deriving artifacts from O(authorities)
extends_documentation_fragment: [jomrr.ca.context, jomrr.ca.context.ownership, jomrr.ca.context.file_mode]
options:
  dest:
    description: Archive path on the managed host.
    version_added: 0.1.0
    type: path
    required: true
  artifacts:
    description: Explicit public artifacts to include. Each item needs C(src), C(file),
      and C(area); when set, this overrides authority-derived artifacts.
    version_added: 0.1.0
    type: list
    default: []
    elements: dict
  authorities:
    description: Managed authorities used to derive default AIA/CDP artifacts.
    version_added: 0.1.0
    type: list
    default: []
    elements: dict
  artifact_mode:
    description: Mode stored for files inside the archive.
    version_added: 0.1.0
    type: str
    default: '0644'
  mode:
    description: Filesystem mode for the generated archive file.
    default: '0600'
"""

EXAMPLES = r"""
- name: Build CA publish archive
  jomrr.ca.publish_archive:
    base_dir: /etc/pki/example
    dest: /tmp/example-public.tar
    authorities: "{{ ca_authorities }}"
    artifact_mode: "0644"
    owner: root
    group: root
    mode: "0600"
"""

RETURN = r"""
path:
  description: Archive path on the managed host.
  type: str
  returned: success
archive_paths:
  description: Relative paths stored in the archive.
  type: list
  returned: success
"""

# Ansible requires DOCUMENTATION, EXAMPLES and RETURN before normal imports.
# pylint: disable=wrong-import-position
import io
import tarfile
from collections.abc import Callable
from typing import Any, cast

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    FileAttributes,
    parse_mode,
    write_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._module import (
    execute_publication,
)
from ansible_collections.jomrr.ca.plugins.module_utils._publish import (
    Artifact,
    publish_argument_spec,
    read_artifacts,
    resolve_artifacts,
)

# pylint: enable=wrong-import-position

MTIME = 0


def _add_bytes(
    archive: tarfile.TarFile,
    path: str,
    content: bytes,
    mode: int,
) -> None:
    """Add bytes to a tar archive with deterministic metadata."""
    info = tarfile.TarInfo(path)
    info.size = len(content)
    info.mtime = MTIME
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    archive.addfile(info, io.BytesIO(content))


def _archive_content(
    artifacts: list[Artifact],
    artifact_mode: Any,
) -> tuple[bytes, list[str]]:
    """Return deterministic tar bytes and paths for public artifacts."""
    mode = parse_mode(artifact_mode, fallback=0o644)
    contents = read_artifacts(artifacts)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for path, content in contents.items():
            _add_bytes(archive, path, content, mode)
    return buffer.getvalue(), sorted(contents)


def _publish_archive(params: dict[str, Any]) -> dict[str, object]:
    """Write the deterministic archive and return its public artifact paths."""
    content, archive_paths = _archive_content(
        resolve_artifacts(params), params["artifact_mode"]
    )
    changed = write_file(
        params["dest"],
        content,
        FileAttributes.from_params(params, "mode"),
        force=params["force"],
    )
    return {"changed": changed, "path": params["dest"], "archive_paths": archive_paths}


def main() -> None:
    """Run the Ansible module for deterministic public publish archives."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec={
            **publish_argument_spec("0600"),
            "artifact_mode": {"type": "str", "default": "0644"},
        },
        supports_check_mode=False,
    )

    execute_publication(module, _publish_archive)


if __name__ == "__main__":
    main()
