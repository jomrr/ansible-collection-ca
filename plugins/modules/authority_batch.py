# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Manage a complete authority graph and its chain exports in one invocation."""

from __future__ import annotations

DOCUMENTATION = r"""
module: authority_batch
short_description: Manage authorities and chains in one parent-first batch
version_added: 1.2.0
description:
- Create or renew a complete managed authority graph and its chain files in one invocation.
- Parents are processed before their children regardless of input order. A root has C(parent
  == name).
- Each authority uses the same issuance, inventory and chain implementation as M(jomrr.ca.authority)
  and M(jomrr.ca.chain).
notes:
- The authority graph lock is held once across the batch. Existing per-authority locks are
  shared with single-module operations.
- Cycles, unknown parents and duplicate names are rejected before writes. Failures stop the
  batch; completed authorities remain managed.
- An empty authority list returns unchanged without creating CA state.
extends_documentation_fragment:
- jomrr.ca.context
- jomrr.ca.context.ownership
- jomrr.ca.context.publishing
- jomrr.ca.context.cryptography
- jomrr.ca.authority_definition.batch
options:
  subject:
    description: Shared subject attributes; authority fields override matching keys.
    type: dict
    default: {}
  renewal:
    description: Shared renewal policy; authority fields override matching keys.
    type: dict
    default: {}
"""

EXAMPLES = r"""
- name: Manage an issuing CA and its root in one invocation
  jomrr.ca.authority_batch:
    base_dir: /etc/pki/example
    ca_name: example
    base_url: http://pki.example.test
    subject: {country: DE, organization: Example}
    authorities:
      - name: issuing
        parent: root
        common_name: Example Issuing CA
        days: 1825
        key_passphrase: "{{ issuing_ca_password }}"
      - name: root
        parent: root
        common_name: Example Root CA
        days: 3650
        key_passphrase: "{{ root_ca_password }}"
  no_log: true
"""

RETURN = r"""
inventory_changed:
  description: Whether any authority inventory state changed.
  type: bool
  returned: success
count:
  description: Number of processed authorities.
  type: int
  returned: success
results:
  description: Per-authority results in parent-first execution order.
  type: list
  elements: dict
  returned: success
  contains:
    name:
      description: Authority identifier.
      type: str
    changed:
      description: Whether authority material, inventory or chains changed.
      type: bool
    cert_path:
      description: Authority PEM certificate path.
      type: str
    csr_path:
      description: Authority CSR path.
      type: str
    chain_paths:
      description: Chain paths keyed by format; root chain files are absent.
      type: dict
    chain_changed:
      description: Whether chain content, attributes or root chain state changed.
      type: bool
    inventory_changed:
      description: Whether authority inventory state changed.
      type: bool
"""

# Ansible requires DOCUMENTATION, EXAMPLES and RETURN before normal imports.
# pylint: disable=wrong-import-position
from collections.abc import Callable
from typing import cast

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._authority_batch import (
    authority_batch_argument_spec,
    ensure_authority_batch,
)
from ansible_collections.jomrr.ca.plugins.module_utils._module import (
    execute_certificate,
)

# pylint: enable=wrong-import-position


def run_module() -> None:
    """Run the authority batch through the standard Ansible lifecycle."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec=authority_batch_argument_spec(), supports_check_mode=False
    )
    execute_certificate(module, ensure_authority_batch)


def main() -> None:
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
