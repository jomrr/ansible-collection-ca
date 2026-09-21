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
extends_documentation_fragment: [jomrr.ca.context, jomrr.ca.context.ownership, jomrr.ca.context.publishing,
  jomrr.ca.context.digest, jomrr.ca.context.formats, jomrr.ca.context.cryptography]
options:
  name:
    description: Authority short name.
    version_added: 0.1.0
    type: str
    required: true
  parent:
    description: Parent CA name. Same as C(name) means self-signed root.
    version_added: 0.1.0
    type: str
    default: ''
  key_type:
    description: Private key algorithm.
    version_added: 0.1.0
    type: str
    default: RSA
    choices:
    - RSA
    - ECDSA
    - P-256
    - P-384
    - Ed25519
    - Ed448
    - EC
    - P256
    - P384
    - ECDSA_P256
    - ECDSA_P384
    - EC_P256
    - EC_P384
    - prime256v1
    - secp256r1
    - secp384r1
    - ED25519
    - ED448
    - EdDSA25519
    - EdDSA448
  key_size:
    description: Key size or ECDSA curve selector. Ignored for Ed25519 and Ed448.
    version_added: 0.1.0
    type: int
    default: 4096
  subject_ordered:
    description: Full ordered subject override. Takes precedence over C(subject), C(common_name),
      and C(email).
    version_added: 0.1.0
    type: list
    default: []
    elements: dict
  common_name:
    description: Common Name. Required unless C(subject_ordered) is set.
    version_added: 0.1.0
    type: str
  email:
    description: Optional subject C(emailAddress).
    version_added: 0.1.0
    type: str
  subject:
    description: Subject defaults used with C(common_name).
    version_added: 0.1.0
    type: dict
    default: {}
  basic_constraints:
    description: Basic Constraints tokens.
    version_added: 0.1.0
    type: list
    elements: str
  key_usage:
    description: Key Usage tokens.
    version_added: 0.1.0
    type: list
    elements: str
  key_usage_critical:
    description: Marks Key Usage critical.
    version_added: 0.1.0
    type: bool
    default: true
  extended_key_usage:
    description: Extended Key Usage values. Usually empty for CAs.
    version_added: 0.1.0
    type: list
    default: []
    elements: str
  extended_key_usage_critical:
    description: Marks Extended Key Usage critical.
    version_added: 0.1.0
    type: bool
    default: false
  san:
    description: Subject Alternative Name entries.
    version_added: 0.1.0
    type: list
    default: []
    elements: str
  san_critical:
    description: Marks SAN critical.
    version_added: 0.1.0
    type: bool
    default: false
  aia_base_url:
    description: Explicit AIA URL prefix. The module appends C(<parent>-ca.der) (the root
      name for a root).
    version_added: 0.1.0
    type: str
    default: ''
  cdp_base_url:
    description: Explicit CDP URL prefix. The module appends C(<parent>-ca.crl) (the root
      name for a root).
    version_added: 0.1.0
    type: str
    default: ''
  raw_extensions:
    description: Additional unrecognized extensions.
    version_added: 0.1.0
    type: list
    default: []
    elements: dict
  pkinit:
    description: Internal PKINIT context for SAN otherName encoding.
    version_added: 0.1.0
    type: dict
    default: {}
  days:
    description: Certificate validity in days.
    version_added: 0.1.0
    type: int
    required: true
  renewal:
    description: Renewal and rekey policy.
    version_added: 0.1.0
    type: dict
    default: {}
  include_identifiers:
    description: Adds SKI and AKI extensions.
    version_added: 0.1.0
    type: bool
    default: true
  key_mode:
    description: Private key file mode.
    version_added: 0.1.0
    type: str
    default: '0600'
  public_mode:
    description: CSR, certificate, DER, text, and inventory file mode.
    version_added: 0.1.0
    type: str
    default: '0644'
  key_passphrase:
    description: Passphrase for the generated authority private key.
    version_added: 0.1.0
    type: str
    required: true
  parent_key_passphrase:
    description: Parent CA private key passphrase for issuing CAs.
    version_added: 0.1.0
    type: str
  certificate_policies:
    description: Certificate policies.
    version_added: 0.1.0
    type: list
    default: []
    elements: dict
  policy_constraints:
    description: Policy constraints.
    version_added: 0.1.0
    type: dict
    default: {}
  inhibit_any_policy:
    description: Inhibit any policy.
    version_added: 0.1.0
    type: raw
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
from typing import Any, cast

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    OPERATION_ERRORS,
    require_cryptography,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory import (
    update_authority_inventory,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509 import (
    ca_authority_argument_spec,
    ensure_x509,
    sanitize_error,
)

# pylint: enable=wrong-import-position

ROOT_CA_DEFAULTS = {
    "basic_constraints": ["CA:TRUE", "pathlen:1"],
    "key_usage": ["keyCertSign", "cRLSign"],
    "digest": "sha384",
}
ISSUING_CA_DEFAULTS = {
    "basic_constraints": ["CA:TRUE", "pathlen:0"],
    "key_usage": ["keyCertSign", "cRLSign"],
    "digest": "sha384",
}


def _apply_authority_defaults(
    params: dict[str, Any], defaults: dict[str, Any]
) -> dict[str, Any]:
    """Apply authority defaults without overriding explicit module values."""
    result = dict(params)
    for key, value in defaults.items():
        if result.get(key) in (None, "", []):
            result[key] = list(value) if isinstance(value, list) else value
    return result


def _authority_params(params: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Return normalized authority parameters and whether it is parent-signed."""
    result = dict(params)
    name = str(result["name"]).strip()
    parent = str(result.get("parent") or name).strip()
    if not name:
        raise ValueError("Authority name must not be empty")
    if not parent:
        parent = name

    signed = parent != name
    defaults = ISSUING_CA_DEFAULTS if signed else ROOT_CA_DEFAULTS
    result = _apply_authority_defaults(result, defaults)
    result["name"] = name
    result["parent"] = parent

    if signed:
        parent_key_passphrase = result.get("parent_key_passphrase")
        if not parent_key_passphrase:
            raise ValueError("Parent-signed authorities require parent_key_passphrase")
        result["signer_key_passphrase"] = parent_key_passphrase

    return result, signed


def run_module() -> None:
    """Run the Ansible module for CA authorities."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec=ca_authority_argument_spec(),
        supports_check_mode=False,
    )

    require_cryptography(module)

    try:
        params, signed = _authority_params(module.params)
        result = ensure_x509(params, signed=signed, authority=True)
        inventory_changed = update_authority_inventory(params, result)
        result["inventory_changed"] = inventory_changed
        result["changed"] = result["changed"] or inventory_changed
    except OPERATION_ERRORS as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))

    module.exit_json(**result)


def main() -> None:
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
