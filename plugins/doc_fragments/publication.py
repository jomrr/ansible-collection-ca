# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Authority definitions accepted by public artifact publishers."""

from dataclasses import dataclass


@dataclass
class ModuleDocFragment:
    """Authority definitions accepted by public artifact publishers."""

    DOCUMENTATION = r"""
options:
  authorities:
    description: Managed authorities used to derive public AIA/CDP files. Only name and parent
      select files; other fields are accepted for reusing authority definitions. Credentials
      are optional and remain protected by Ansible C(no_log).
    type: list
    elements: dict
    suboptions:
      name: {description: 'Authority name identifying the public files.',
        type: str, required: true}
      formats: {description: 'Authority metadata, unused by publication.', type: list, elements: str}
      key_type:
        description: Authority metadata, unused by publication.
        type: str
        choices: [RSA, ECDSA, P-256, P-384, Ed25519, Ed448, EC, P256, P384, ECDSA_P256, ECDSA_P384,
          EC_P256, EC_P384, prime256v1, secp256r1, secp384r1, ED25519, ED448, EdDSA25519,
          EdDSA448]
      key_size: {description: 'Authority metadata, unused by publication.', type: int}
      subject_ordered: {description: 'Authority metadata, unused by publication.', type: list,
        elements: dict}
      common_name: {description: 'Authority metadata, unused by publication.', type: str}
      email: {description: 'Authority metadata, unused by publication.', type: str}
      subject: {description: 'Authority metadata, unused by publication.', type: dict}
      basic_constraints: {description: 'Authority metadata, unused by publication.', type: list,
        elements: str}
      key_usage: {description: 'Authority metadata, unused by publication.', type: list, elements: str}
      key_usage_critical: {description: 'Authority metadata, unused by publication.', type: bool}
      extended_key_usage: {description: 'Authority metadata, unused by publication.', type: list,
        elements: str}
      extended_key_usage_critical: {description: 'Authority metadata, unused by publication.',
        type: bool}
      san: {description: 'Authority metadata, unused by publication.', type: list, elements: str}
      san_critical: {description: 'Authority metadata, unused by publication.', type: bool}
      aia_base_url: {description: 'Authority metadata, unused by publication.', type: str}
      cdp_base_url: {description: 'Authority metadata, unused by publication.', type: str}
      raw_extensions: {description: 'Authority metadata, unused by publication.', type: list,
        elements: dict}
      pkinit: {description: 'Authority metadata, unused by publication.', type: dict}
      days: {description: 'Authority metadata, unused by publication.', type: int}
      renewal: {description: 'Authority metadata, unused by publication.', type: dict}
      digest:
        description: Authority metadata, unused by publication.
        type: str
        choices: [sha224, sha256, sha384, sha512]
      include_identifiers: {description: 'Authority metadata, unused by publication.', type: bool}
      key_mode: {description: 'Authority metadata, unused by publication.', type: str}
      public_mode: {description: 'Authority metadata, unused by publication.', type: str}
      key_passphrase: {description: 'Authority metadata, unused by publication. Protected
          by Ansible C(no_log).', type: str}
      certificate_policies: {description: 'Authority metadata, unused by publication.', type: list,
        elements: dict}
      policy_constraints: {description: 'Authority metadata, unused by publication.', type: dict}
      inhibit_any_policy: {description: 'Authority metadata, unused by publication.', type: raw}
      parent: {type: str, description: 'Parent name, used to identify a self-signed root.'}
      parent_key_passphrase: {type: str, description: 'Authority metadata, unused by publication.
          Protected by Ansible C(no_log).'}
      default_days: {type: int, description: 'Authority metadata, unused by publication.'}
      crl_days: {type: int, description: 'Authority metadata, unused by publication.'}
      crl_renew_before_days: {type: float, description: 'Authority metadata, unused by publication.'}
      crl_digest: {type: str, description: 'Authority metadata, unused by publication.'}
      legacy_generation: {type: str, description: 'Authority metadata, unused by publication.'}
      archived_key_passphrases: {type: dict, description: 'Authority metadata, unused by publication.
          Protected by Ansible C(no_log).'}
    default: []
"""
