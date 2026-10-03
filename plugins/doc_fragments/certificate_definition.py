# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""One shared nested certificate schema for single and batch documentation."""

from dataclasses import dataclass
from typing import ClassVar

import yaml


def _authority_definitions(certificate_documentation: str) -> str:
    """Reuse field types and choices when documenting full authority definitions."""
    fields = yaml.safe_load(certificate_documentation)["options"]["certificate"][
        "suboptions"
    ]
    certificate_only = {
        "type",
        "csr_path",
        "csr_content",
        "output_dir",
        "directory_mode",
        "friendly_name",
        "pfx_passphrase",
        "passphrase",
        "krb5_realm",
        "ad_object_guid",
        "fritzbox_deploy",
    }
    options = {
        name: {
            **field,
            "description": (
                f"Authority {name.replace('_', ' ')} metadata. "
                "Accepted for reusing definitions; unused by the dispatcher."
            ),
        }
        for name, field in fields.items()
        if name not in certificate_only
    }
    options["name"]["description"] = (
        "Authority name matched by C(certificate_types[type].issuer)."
    )
    options["key_passphrase"].update(
        required=True,
        description=(
            "Selected issuer private key password. Protected by Ansible C(no_log)."
        ),
    )
    options.update(
        {
            "parent": {
                "type": "str",
                "description": "Parent name, used to identify a self-signed root.",
            },
            "parent_key_passphrase": {
                "type": "str",
                "description": (
                    "Parent key password metadata, protected by Ansible C(no_log)."
                ),
            },
            "default_days": {
                "type": "int",
                "description": (
                    "Default lifetime for certificates issued by this authority."
                ),
            },
            "crl_days": {
                "type": "int",
                "description": "CRL lifetime metadata, unused by the dispatcher.",
            },
            "crl_renew_before_days": {
                "type": "float",
                "description": "CRL renewal window metadata, unused by the dispatcher.",
            },
            "crl_digest": {
                "type": "str",
                "description": "CRL digest metadata, unused by the dispatcher.",
            },
            "legacy_generation": {
                "type": "str",
                "description": (
                    "Legacy publication identity metadata, unused by the dispatcher."
                ),
            },
            "archived_key_passphrases": {
                "type": "dict",
                "description": (
                    "Generation ID to password mapping. Ansible masks the entire "
                    "mapping, including keys. Unused by the dispatcher."
                ),
            },
        }
    )
    return yaml.safe_dump(
        {
            "options": {
                "authorities": {
                    "description": (
                        "Authority definitions used to resolve issuer credentials "
                        "and default lifetimes."
                    ),
                    "type": "list",
                    "elements": "dict",
                    "required": True,
                    "suboptions": options,
                }
            }
        },
        sort_keys=False,
    )


@dataclass
class ModuleDocFragment:
    """Ansible documentation fragments for the two dispatcher argument names."""

    DOCUMENTATION: ClassVar[str] = r"""
options:
  certificate:
    description: Declarative certificate definition. Unknown fields are rejected; pass only
      the documented schema.
    type: dict
    required: true
    suboptions:
      name:
        description: Managed object name used for files and inventory.
        type: str
        required: true
      formats:
        description: Requested export formats; omitted values use the selected profile defaults.
        type: list
        elements: str
      key_type:
        description: Private key algorithm.
        type: str
        choices: [RSA, ECDSA, P-256, P-384, Ed25519, Ed448, EC, P256, P384,
          ECDSA_P256, ECDSA_P384, EC_P256, EC_P384, prime256v1, secp256r1,
          secp384r1, ED25519, ED448, EdDSA25519, EdDSA448]
      key_size:
        description: Key size or ECDSA curve selector. Ignored for Ed25519 and Ed448.
        type: int
      subject_ordered:
        description: Full ordered subject override. Takes precedence over C(subject), C(common_name),
          and C(email).
        type: list
        elements: dict
      common_name:
        description: Common Name. Required unless C(subject_ordered) is set.
        type: str
      email:
        description: Optional subject C(emailAddress).
        type: str
      subject:
        description: Subject defaults used with C(common_name).
        type: dict
      basic_constraints:
        description: Basic Constraints tokens.
        type: list
        elements: str
      key_usage:
        description: Key Usage tokens.
        type: list
        elements: str
      key_usage_critical:
        description: Marks Key Usage critical.
        type: bool
      extended_key_usage:
        description: Extended Key Usage overrides; omitted or empty values use the selected profile defaults.
        type: list
        elements: str
      extended_key_usage_critical:
        description: Marks Extended Key Usage critical.
        type: bool
      san:
        description: Subject Alternative Name entries.
        type: list
        elements: str
      san_critical:
        description: Marks SAN critical.
        type: bool
      aia_base_url:
        description: Explicit AIA URL prefix. The module appends C(<parent>-ca.der) (the
          root name for a root), with a generation suffix after a key or subject change.
        type: str
      cdp_base_url:
        description: Explicit CDP URL prefix. The module appends C(<parent>-ca.crl) (the
          root name for a root), with a generation suffix after a key or subject change.
        type: str
      raw_extensions:
        description: Additional unrecognized extensions.
        type: list
        elements: dict
      pkinit:
        description: Internal PKINIT context for SAN otherName encoding.
        type: dict
      days:
        description: Certificate lifetime in days; defaults to the selected authority C(default_days).
        type: int
      renewal:
        description: Renewal and rekey policy.
        type: dict
      digest:
        description: Signature digest; defaults to the selected profile digest.
        type: str
        choices:
        - sha224
        - sha256
        - sha384
        - sha512
      include_identifiers:
        description: Adds SKI and AKI extensions.
        type: bool
      key_mode:
        description: Private key file mode.
        type: str
      public_mode:
        description: CSR, certificate, DER, text, and inventory file mode.
        type: str
      key_passphrase:
        description: Optional managed private key password, protected by Ansible C(no_log).
          Unused for external CSRs.
        type: str
      certificate_policies:
        description: Certificate policies.
        type: list
        elements: dict
      policy_constraints:
        description: Policy constraints.
        type: dict
      inhibit_any_policy:
        description: Inhibit any policy.
        type: raw
      type:
        description: Built-in certificate profile; defaults and issuer come from this type.
        type: str
        required: true
      csr_path:
        description: External PEM CSR path on the managed CA host; mutually exclusive with
          C(csr_content).
        type: path
      csr_content:
        description: External PEM CSR content; mutually exclusive with C(csr_path).
        type: str
      output_dir:
        description: Certificate export directory; defaults to C(<base_dir>/certs/<name>).
        type: path
      directory_mode:
        description: Certificate directory permissions; defaults to C(0755).
        type: str
      friendly_name:
        description: PKCS#12 friendly name; defaults to the common name or object name.
        type: str
      pfx_passphrase:
        description: PKCS#12 export password. Protected by Ansible C(no_log).
        type: str
      passphrase:
        description: Alternate PKCS#12 password, taking precedence over C(pfx_passphrase).
          Protected by Ansible C(no_log).
        type: str
      krb5_realm:
        description: PKINIT realm for C(mskdc); defaults to O(kerberos_realm).
        type: str
      ad_object_guid:
        description: AD object GUID for C(mskdc), in canonical GUID or raw hexadecimal form.
        type: str
      fritzbox_deploy:
        description: Optional deployment settings, accepted for reusing certificate definitions.
          Issuance does not deploy the certificate. Use M(jomrr.ca.fritzbox_deploy) separately.
        type: dict
        suboptions:
          enabled:
            description: Deployment enable flag, unused by the certificate dispatcher.
            type: bool
          url:
            description: Deployment endpoint, unused by the certificate dispatcher.
            type: str
          username:
            description: Deployment user name, unused by the certificate dispatcher.
            type: str
          password:
            description: Deployment password, protected by Ansible C(no_log).
            type: str
          timeout:
            description: Deployment timeout, unused by the certificate dispatcher.
            type: int
          validate_certs:
            description: Deployment TLS setting, unused by the certificate dispatcher.
            type: bool
"""

    BATCH: ClassVar[str] = DOCUMENTATION.replace(
        "  certificate:", "  certificates:", 1
    ).replace("    type: dict", "    type: list\n    elements: dict", 1)

    AUTHORITIES: ClassVar[str] = _authority_definitions(DOCUMENTATION)
