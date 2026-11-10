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
- Manage destination directory ownership and permissions separately.
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
from pathlib import Path
from typing import cast

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    OPERATION_ERRORS,
    require_cryptography,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    FileAttributes,
    file_locks,
    sanitize_error,
    write_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._publish import (
    publish_argument_spec,
    publish_lock_paths,
    read_artifacts,
    resolve_artifacts,
)

# pylint: enable=wrong-import-position


def run_module() -> None:
    """Publish the selected public files in one managed-host operation."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec=publish_argument_spec("0644"),
        supports_check_mode=False,
    )
    params = module.params
    try:
        if not params["artifacts"]:
            require_cryptography(module)
        with file_locks(publish_lock_paths(params)):
            contents = read_artifacts(resolve_artifacts(params))
            attrs = FileAttributes.from_params(params, "mode")
            changed = False
            for path, content in contents.items():
                changed = (
                    write_file(
                        str(Path(params["dest"]) / path),
                        content,
                        attrs,
                        force=params["force"],
                    )
                    or changed
                )
    except OPERATION_ERRORS as exc:
        module.fail_json(msg=sanitize_error(exc, params))
    module.exit_json(
        changed=changed, path=params["dest"], published_paths=sorted(contents)
    )


def main() -> None:
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
