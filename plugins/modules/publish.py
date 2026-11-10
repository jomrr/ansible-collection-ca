# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Publish public AIA/CDP files directly on the CA host."""

from __future__ import annotations

DOCUMENTATION = r"""
module: publish
short_description: Publish public AIA/CDP files directly on the CA host
version_added: 1.2.0
description:
- Write public certificates, issuing chains and CRLs below O(dest)/aia and O(dest)/crl.
- Use the same retained issuer generations and filenames as M(jomrr.ca.publish_archive).
- Run M(jomrr.ca.crl) before publication. Missing active artifacts cause failure;
  retired generations retain their certificates and any existing final CRL.
- Compare content and attributes on each run and restore missing or altered files.
  Unrelated destination files are preserved.
requirements:
- cryptography >= 43 on the managed host when deriving artifacts from O(authorities)
notes:
- The execution user needs access to CA data and locks and permission to write O(dest).
  Use privilege escalation as required.
- Manage O(dest), O(dest)/aia and O(dest)/crl with O(owner), O(group) and O(directory_mode).
- Check mode compares directories and files without creating locks or writing artifacts.
attributes:
  check_mode:
    support: full
    description: Predict directory, content and permission changes without writes.
extends_documentation_fragment: [jomrr.ca.context, jomrr.ca.context.ownership]
options:
  dest:
    description: Webroot directory on the CA host.
    type: path
    required: true
  authorities:
    description: Managed authorities used to derive public files for every retained generation.
    type: list
    elements: dict
    default: []
  artifacts:
    description:
    - Explicit public files overriding O(authorities). Each item needs C(src), C(file),
      and C(area). Areas are C(aia), C(cdp) or C(crl); C(file) must be a plain filename.
    - Include all required generations and preserve their original issuer URLs.
    type: list
    elements: dict
    default: []
  mode:
    description: Filesystem mode for published files.
    type: str
    default: '0644'
  directory_mode:
    description: Filesystem mode for the webroot and its aia and crl directories.
    type: str
    default: '0755'
    version_added: 1.3.0
"""

EXAMPLES = r"""
- name: Publish directly into the CA host webroot
  become: true
  become_user: root
  jomrr.ca.publish:
    base_dir: /etc/pki/example
    dest: /var/www/pki
    authorities: "{{ ca_authorities }}"
    owner: root
    group: root
    mode: "0644"
"""

RETURN = r"""
path:
  description: Destination webroot on the CA host.
  type: str
  returned: success
published_paths:
  description: Sorted paths relative to the destination webroot.
  type: list
  elements: str
  returned: success
"""

# Ansible requires DOCUMENTATION, EXAMPLES and RETURN before normal imports.
# pylint: disable=wrong-import-position
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any, cast

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    FileAttributes,
    ensure_directory,
    write_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._module import (
    execute_publication,
)
from ansible_collections.jomrr.ca.plugins.module_utils._publish import (
    publish_argument_spec,
    read_artifacts,
    resolve_artifacts,
)

# pylint: enable=wrong-import-position


def _publish_files(
    params: dict[str, Any], *, check_mode: bool = False
) -> dict[str, object]:
    """Write all selected public artifacts before returning their change state."""
    contents = read_artifacts(resolve_artifacts(params))
    attrs = FileAttributes.from_params(params, "mode")
    directories = FileAttributes(
        params["owner"], params["group"], params.get("directory_mode", "0755")
    )
    changed = False
    for directory in ("", "aia", "crl"):
        changed = (
            ensure_directory(
                str(Path(params["dest"]) / directory),
                directories,
                check_mode=check_mode,
            )
            or changed
        )
    for path, content in contents.items():
        changed = (
            write_file(
                str(Path(params["dest"]) / path),
                content,
                attrs,
                force=params["force"],
                check_mode=check_mode,
            )
            or changed
        )
    return {
        "changed": changed,
        "path": params["dest"],
        "published_paths": sorted(contents),
    }


def main() -> None:
    """Publish the selected public files in one managed-host operation."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec={
            **publish_argument_spec("0644"),
            "directory_mode": {"type": "str", "default": "0755"},
        },
        supports_check_mode=True,
    )
    execute_publication(module, partial(_publish_files, check_mode=module.check_mode))


if __name__ == "__main__":
    main()
