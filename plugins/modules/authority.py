# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Manage a CA authority certificate."""

from __future__ import annotations

DOCUMENTATION = r"""
module: authority
short_description: Manage a CA authority certificate
version_added: 0.1.0
description:
- Manage a CA authority certificate.
notes:
- Before CA rekey, retain the previous public issuer identity. Its existing AIA/CDP
  URLs remain pinned to it; new generations receive a filename suffix derived from
  their public key and complete subject. Same-key, same-subject renewal keeps its URLs.
- After rollover, run M(jomrr.ca.crl) and M(jomrr.ca.publish_archive) with C(authorities)
  on the publication module to refresh every generation before deploying new leaves.
  Keep archived keys until M(jomrr.ca.crl) reports their generation as retired.
  Retirement is bounded by the last issued certificate expiry and the old CA expiry.
- Earlier rollovers can be recovered from archived certificates and keys. If multiple
  generations used the same legacy URLs, run M(jomrr.ca.crl) with C(legacy_generation)
  to choose their owner, then reissue or revoke its reported C(migration_conflicts).
- Managed keys associated with locally recorded C(key_compromise) or C(ca_compromise)
  revocations cannot be reused. Request C(renewal.rekey=true) for a due renewal or
  C(force=true) to generate a new key immediately.
- Parent-signed authorities are checked against the Basic Constraints, certificate-signing
  Key Usage and path length limits of the complete managed issuer chain before writing
  key, CSR or certificate material.
- A root with C(pathlen:1) can issue another CA with C(pathlen:0). An issuing CA with
  C(pathlen:0) cannot issue a further non-self-issued CA usable for leaf issuance.
- Path limits count CA levels, not the number of sibling authorities. Self-issued
  CA rollover certificates do not consume a level.
extends_documentation_fragment: [jomrr.ca.context, jomrr.ca.context.ownership, jomrr.ca.context.publishing,
  jomrr.ca.context.digest, jomrr.ca.context.formats, jomrr.ca.context.cryptography, jomrr.ca.authority_definition]
"""

EXAMPLES = r"""
- name: Create root CA
  jomrr.ca.authority:
    base_dir: /etc/pki/example
    ca_name: example
    base_url: http://pki.example.test
    name: root
    parent: root
    common_name: Example Root CA
    subject: {country: DE, organization: Example, organizational_unit: Example PKI}
    days: 3650
    key_passphrase: "{{ ca_root_passphrase }}"

- name: Create component CA
  jomrr.ca.authority:
    base_dir: /etc/pki/example
    ca_name: example
    base_url: http://pki.example.test
    name: component
    parent: root
    common_name: Example Component CA
    subject: {country: DE, organization: Example, organizational_unit: Example PKI}
    days: 1825
    key_passphrase: "{{ ca_component_passphrase }}"
    parent_key_passphrase: "{{ ca_root_passphrase }}"
    renewal:
      renew_before_days: 30
      rekey: true
"""

RETURN = r"""
generation_changed:
  description: Whether retained public issuer material or legacy URL state changed.
  type: bool
  returned: success
  version_added: 1.1.0
directory_changed:
  description: Always C(false) for authorities.
  type: bool
  returned: success
chain_changed:
  description: Always C(false) for authorities.
  type: bool
  returned: success
extends_documentation_fragment: [jomrr.ca.certificate]
"""

# Ansible requires DOCUMENTATION, EXAMPLES and RETURN before normal imports.
# pylint: disable=wrong-import-position
from collections.abc import Callable
from typing import cast

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._authority import (
    ensure_authority,
)
from ansible_collections.jomrr.ca.plugins.module_utils._module import (
    execute_certificate,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_params import (
    ca_authority_argument_spec,
)

# pylint: enable=wrong-import-position


def run_module() -> None:
    """Run the Ansible module for CA authorities."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec=ca_authority_argument_spec(),
        supports_check_mode=False,
    )

    execute_certificate(module, ensure_authority)


def main() -> None:
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
