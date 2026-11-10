# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared authority fields for single-module and nested batch documentation."""

from dataclasses import dataclass
from typing import Any, ClassVar

import yaml
from ansible_collections.jomrr.ca.plugins.doc_fragments.certificate_definition import (
    ModuleDocFragment as CertificateDefinition,
)
from ansible_collections.jomrr.ca.plugins.doc_fragments.certificate_definition import (
    authority_list_documentation,
)
from ansible_collections.jomrr.ca.plugins.doc_fragments.context import (
    ModuleDocFragment as Context,
)


def _batch_definitions(documentation: str) -> str:
    """Nest the authority fields, retaining defaults in the issuance engine."""
    fields: dict[str, Any] = yaml.safe_load(documentation)["options"]
    for fragment in (Context.DIGEST, Context.FORMATS):
        fields.update(yaml.safe_load(fragment)["options"])
    for field in fields.values():
        field.pop("version_added", None)
        field.pop("default", None)
    metadata = yaml.safe_load(CertificateDefinition.AUTHORITIES)["options"][
        "authorities"
    ]["suboptions"]
    fields.update(
        {name: value for name, value in metadata.items() if name not in fields}
    )
    fields["parent"]["required"] = True
    descriptions = {
        "formats": (
            "Authority certificate exports; defaults to PEM, DER and text. "
            "Chains always use all three formats."
        ),
        "subject": "Authority subject overrides merged with O(subject).",
        "renewal": "Authority renewal overrides merged with O(renewal).",
        "key_passphrase": (
            "Non-empty authority private key passphrase, "
            "protected by Ansible C(no_log)."
        ),
        "parent_key_passphrase": (
            "Accepted as metadata; the parent credential is resolved "
            "from the matching authority entry."
        ),
    }
    for name, description in descriptions.items():
        fields[name]["description"] = description
    return authority_list_documentation(
        fields,
        "Managed authority definitions. Parent key passphrases are resolved "
        "from this same list.",
    )


@dataclass
class ModuleDocFragment:
    """Authority module fields and their batch representation."""

    DOCUMENTATION: ClassVar[str] = r"""
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
      name for a root), with a generation suffix after a key or subject change.
    version_added: 0.1.0
    type: str
    default: ''
  cdp_base_url:
    description: Explicit CDP URL prefix. The module appends C(<parent>-ca.crl) (the root
      name for a root), with a generation suffix after a key or subject change.
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

    BATCH: ClassVar[str] = _batch_definitions(DOCUMENTATION)
