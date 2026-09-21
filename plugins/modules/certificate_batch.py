# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Dispatch managed CA collection certificates in one batch."""

from __future__ import annotations

DOCUMENTATION = r"""
module: certificate_batch
short_description: Dispatch managed CA collection certificates in one batch
version_added: 0.1.0
description:
- Dispatch managed CA collection certificates in one batch.
extends_documentation_fragment: [jomrr.ca.context, jomrr.ca.context.ownership, jomrr.ca.context.publishing,
  jomrr.ca.context.cryptography, jomrr.ca.context.dispatch_notes, jomrr.ca.certificate]
options:
  subject:
    description: Role-level subject defaults.
    version_added: 0.1.0
    type: dict
    default: {}
  renewal:
    description: Module-level renewal policy defaults. Certificate-local C(renewal) overrides
      these values.
    version_added: 0.1.0
    type: dict
    default: {}
  certificates:
    description: Certificate models. See ca_certificate.
    version_added: 0.1.0
    type: list
    required: true
    elements: dict
  base_url:
    description: Base publication URL for derived AIA/CDP URLs.
"""

EXAMPLES = r"""
- name: Issue managed certificates
  jomrr.ca.certificate_batch:
    base_dir: /etc/pki/example
    ca_name: example
    base_url: http://pki.example.test
    certificates: "{{ ca_certificates }}"
    certificate_types: "{{ ca_certificate_types }}"
    authorities: "{{ ca_authorities }}"
    subject: "{{ ca_subject }}"
    renewal: "{{ ca_renewal }}"
    owner: root
    group: root
"""

RETURN = r"""
inventory_changed:
  description: Whether the composed inventory or any certificate inventory fragment changed.
  type: bool
  returned: success
count:
  description: Number of certificate models processed.
  type: int
  returned: success
issuer_groups:
  description: Number of processed certificates by issuer.
  type: dict
  returned: success
results:
  description: Per-certificate result dictionaries in the same order as C(certificates).
  type: list
  returned: success
  elements: dict
"""

# Ansible requires DOCUMENTATION, EXAMPLES and RETURN before normal imports.
# pylint: disable=wrong-import-position
from collections.abc import Callable
from typing import cast

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_engine import (
    batch_certificate_argument_spec,
    ensure_certificate_batch,
)
from ansible_collections.jomrr.ca.plugins.module_utils._module import (
    execute_certificate,
)

# pylint: enable=wrong-import-position


def run_module() -> None:
    """Run the Ansible module for batched certificate profiles."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec=batch_certificate_argument_spec(),
        supports_check_mode=False,
    )

    execute_certificate(module, ensure_certificate_batch)


def main() -> None:
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
