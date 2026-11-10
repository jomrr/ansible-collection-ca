# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Manage an ordered PEM certificate chain on the managed host."""

from __future__ import annotations

DOCUMENTATION = r"""
module: chain
short_description: Manage an ordered PEM certificate chain on the managed host
version_added: 0.1.0
description:
- Manage an ordered PEM certificate chain on the managed host.
extends_documentation_fragment: [jomrr.ca.context, jomrr.ca.context.ownership, jomrr.ca.context.formats,
  jomrr.ca.context.file_mode, jomrr.ca.context.cryptography]
options:
  name:
    description: Authority short name. The module expects C(<base_dir>/ca/<name>-ca.pem).
    version_added: 0.1.0
    type: str
    required: true
  formats:
    description: Chain output formats.
"""

EXAMPLES = r"""
- name: Create component CA chain
  jomrr.ca.chain:
    base_dir: /etc/pki/example
    name: component
    owner: root
    group: root

- name: Normalize root CA chain state
  jomrr.ca.chain:
    base_dir: /etc/pki/example
    name: root
"""

RETURN = r"""
path:
  description: Derived stable PEM chain path.
  type: str
  returned: success
paths:
  description: Derived stable chain paths keyed by format.
  type: dict
  returned: success
state:
  description: C(present) for issuing CA chains, C(absent) for root CA chains.
  type: str
  returned: success
"""

# Ansible requires DOCUMENTATION, EXAMPLES and RETURN before normal imports.
# pylint: disable=wrong-import-position
from collections.abc import Callable
from typing import cast

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._chain import (
    ensure_authority_chain,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import file_argument_spec
from ansible_collections.jomrr.ca.plugins.module_utils._module import (
    execute_certificate,
)

# pylint: enable=wrong-import-position


def run_module() -> None:
    """Run the Ansible module for CA chain files."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "name": {"type": "str", "required": True},
            "formats": {
                "type": "list",
                "elements": "str",
                "default": ["pem", "der", "txt"],
            },
            **file_argument_spec(),
        },
        supports_check_mode=False,
    )

    execute_certificate(module, ensure_authority_chain)


def main() -> None:
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
