# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared authority fields for single-module and nested batch documentation."""

from dataclasses import dataclass


@dataclass
class ModuleDocFragment:
    """Ansible documentation fragments with statically readable values."""

    DOCUMENTATION = r"""
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

    BATCH = r"""
options:
  authorities:
    description: Managed authority definitions. Parent key passphrases are resolved from this
      same list.
    type: list
    elements: dict
    required: true
    suboptions:
      name: {description: Authority short name., type: str, required: true}
      parent: {description: Parent CA name. Same as C(name) means self-signed root., type: str,
        required: true}
      key_type:
        description: Private key algorithm for the managed CA.
        type: str
        choices: [RSA, ECDSA, P-256, P-384, Ed25519, Ed448, EC, P256, P384, ECDSA_P256, ECDSA_P384,
          EC_P256, EC_P384, prime256v1, secp256r1, secp384r1, ED25519, ED448, EdDSA25519,
          EdDSA448]
      key_size: {description: CA key size or ECDSA curve selector. Ignored for Ed25519 and
          Ed448., type: int}
      subject_ordered: {description: 'Full ordered CA subject override. Takes precedence over
          C(subject), C(common_name), and C(email).', type: list, elements: dict}
      common_name: {description: CA Common Name. Required unless C(subject_ordered) is set.,
        type: str}
      email: {description: Optional CA subject C(emailAddress)., type: str}
      subject: {description: Authority subject overrides merged with O(subject)., type: dict}
      basic_constraints: {description: Basic Constraints tokens for the CA certificate., type: list,
        elements: str}
      key_usage: {description: Key Usage tokens for the CA certificate., type: list, elements: str}
      key_usage_critical: {description: Marks CA certificate Key Usage critical., type: bool}
      extended_key_usage: {description: Extended Key Usage values. Usually empty for CAs.,
        type: list, elements: str}
      extended_key_usage_critical: {description: Marks CA certificate Extended Key Usage critical.,
        type: bool}
      san: {description: Subject Alternative Name entries., type: list, elements: str}
      san_critical: {description: Marks CA certificate SAN critical., type: bool}
      aia_base_url: {description: 'Explicit CA AIA URL prefix. The module appends C(<parent>-ca.der)
          (the root name for a root), with a generation suffix after a key or subject change.',
        type: str}
      cdp_base_url: {description: 'Explicit CA CDP URL prefix. The module appends C(<parent>-ca.crl)
          (the root name for a root), with a generation suffix after a key or subject change.',
        type: str}
      raw_extensions: {description: Additional unrecognized extensions for the CA certificate.,
        type: list, elements: dict}
      pkinit: {description: Internal PKINIT context for CA SAN otherName encoding., type: dict}
      days: {description: Certificate validity in days., type: int, required: true}
      renewal: {description: Authority renewal overrides merged with O(renewal)., type: dict}
      include_identifiers: {description: Adds SKI and AKI extensions to the CA certificate.,
        type: bool}
      key_mode: {description: CA private key file mode., type: str}
      public_mode: {description: 'CA CSR, certificate, DER, text, and inventory file mode.',
        type: str}
      key_passphrase: {description: 'Non-empty authority private key passphrase, protected
          by Ansible C(no_log).', type: str, required: true}
      parent_key_passphrase: {description: Accepted as metadata; the parent credential is
          resolved from the matching authority entry., type: str}
      certificate_policies: {description: Certificate policies for the CA certificate., type: list,
        elements: dict}
      policy_constraints: {description: Policy constraints for the CA certificate., type: dict}
      inhibit_any_policy: {description: Inhibit any policy for the CA certificate., type: raw}
      digest:
        description: Signature digest for RSA and ECDSA keys.
        type: str
        choices: [sha224, sha256, sha384, sha512]
      formats: {description: 'Authority certificate exports; defaults to PEM, DER and text.
          Optional C(cer) writes DER bytes with a C(.cer) extension. Chains always use PEM,
          DER and text.', type: list, elements: str}
      default_days: {type: int, description: Default lifetime for certificates issued by this
          authority.}
      crl_days: {type: int, description: 'CRL lifetime metadata, unused by the dispatcher.'}
      crl_renew_before_days: {type: float, description: 'CRL renewal window metadata, unused
          by the dispatcher.'}
      crl_digest: {type: str, description: 'CRL digest metadata, unused by the dispatcher.'}
      legacy_generation: {type: str, description: 'Legacy publication identity metadata, unused
          by the dispatcher.'}
      archived_key_passphrases: {type: dict, description: 'Generation ID to password mapping.
          Ansible masks the entire mapping, including keys. Unused by the dispatcher.'}
"""

    ISSUERS = r"""
options:
  authorities:
    description: Authority definitions used to resolve issuer credentials and default lifetimes.
    type: list
    elements: dict
    required: true
    suboptions:
      name: {description: 'Authority name matched by C(certificate_types[type].issuer).',
        type: str, required: true}
      formats: {description: Authority formats metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: list, elements: str}
      key_type:
        description: Authority key type metadata. Accepted for reusing definitions; unused
          by the dispatcher.
        type: str
        choices: [RSA, ECDSA, P-256, P-384, Ed25519, Ed448, EC, P256, P384, ECDSA_P256, ECDSA_P384,
          EC_P256, EC_P384, prime256v1, secp256r1, secp384r1, ED25519, ED448, EdDSA25519,
          EdDSA448]
      key_size: {description: Authority key size metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: int}
      subject_ordered: {description: Authority subject ordered metadata. Accepted for reusing
          definitions; unused by the dispatcher., type: list, elements: dict}
      common_name: {description: Authority common name metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: str}
      email: {description: Authority email metadata. Accepted for reusing definitions; unused
          by the dispatcher., type: str}
      subject: {description: Authority subject metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: dict}
      basic_constraints: {description: Authority basic constraints metadata. Accepted for
          reusing definitions; unused by the dispatcher., type: list, elements: str}
      key_usage: {description: Authority key usage metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: list, elements: str}
      key_usage_critical: {description: Authority key usage critical metadata. Accepted for
          reusing definitions; unused by the dispatcher., type: bool}
      extended_key_usage: {description: Authority extended key usage metadata. Accepted for
          reusing definitions; unused by the dispatcher., type: list, elements: str}
      extended_key_usage_critical: {description: Authority extended key usage critical metadata.
          Accepted for reusing definitions; unused by the dispatcher., type: bool}
      san: {description: Authority san metadata. Accepted for reusing definitions; unused
          by the dispatcher., type: list, elements: str}
      san_critical: {description: Authority san critical metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: bool}
      aia_base_url: {description: Authority aia base url metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: str}
      cdp_base_url: {description: Authority cdp base url metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: str}
      raw_extensions: {description: Authority raw extensions metadata. Accepted for reusing
          definitions; unused by the dispatcher., type: list, elements: dict}
      pkinit: {description: Authority pkinit metadata. Accepted for reusing definitions; unused
          by the dispatcher., type: dict}
      days: {description: Authority days metadata. Accepted for reusing definitions; unused
          by the dispatcher., type: int}
      renewal: {description: Authority renewal metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: dict}
      digest:
        description: Authority digest metadata. Accepted for reusing definitions; unused by
          the dispatcher.
        type: str
        choices: [sha224, sha256, sha384, sha512]
      include_identifiers: {description: Authority include identifiers metadata. Accepted
          for reusing definitions; unused by the dispatcher., type: bool}
      key_mode: {description: Authority key mode metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: str}
      public_mode: {description: Authority public mode metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: str}
      key_passphrase: {description: Selected issuer private key password. Protected by Ansible
          C(no_log)., type: str, required: true}
      certificate_policies: {description: Authority certificate policies metadata. Accepted
          for reusing definitions; unused by the dispatcher., type: list, elements: dict}
      policy_constraints: {description: Authority policy constraints metadata. Accepted for
          reusing definitions; unused by the dispatcher., type: dict}
      inhibit_any_policy: {description: Authority inhibit any policy metadata. Accepted for
          reusing definitions; unused by the dispatcher., type: raw}
      parent: {type: str, description: 'Parent name, used to identify a self-signed root.'}
      parent_key_passphrase: {type: str, description: 'Parent key password metadata, protected
          by Ansible C(no_log).'}
      default_days: {type: int, description: Default lifetime for certificates issued by this
          authority.}
      crl_days: {type: int, description: 'CRL lifetime metadata, unused by the dispatcher.'}
      crl_renew_before_days: {type: float, description: 'CRL renewal window metadata, unused
          by the dispatcher.'}
      crl_digest: {type: str, description: 'CRL digest metadata, unused by the dispatcher.'}
      legacy_generation: {type: str, description: 'Legacy publication identity metadata, unused
          by the dispatcher.'}
      archived_key_passphrases: {type: dict, description: 'Generation ID to password mapping.
          Ansible masks the entire mapping, including keys. Unused by the dispatcher.'}
"""

    CRL = r"""
options:
  authorities:
    description: Authority definitions. Only CRL fields and credentials are used; other fields
      are accepted as metadata.
    type: list
    elements: dict
    required: true
    suboptions:
      name: {description: Existing authority whose CRLs are managed., type: str, required: true}
      formats: {description: Authority formats metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: list, elements: str}
      key_type:
        description: Authority key type metadata. Accepted for reusing definitions; unused
          by the dispatcher.
        type: str
        choices: [RSA, ECDSA, P-256, P-384, Ed25519, Ed448, EC, P256, P384, ECDSA_P256, ECDSA_P384,
          EC_P256, EC_P384, prime256v1, secp256r1, secp384r1, ED25519, ED448, EdDSA25519,
          EdDSA448]
      key_size: {description: Authority key size metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: int}
      subject_ordered: {description: Authority subject ordered metadata. Accepted for reusing
          definitions; unused by the dispatcher., type: list, elements: dict}
      common_name: {description: Authority common name metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: str}
      email: {description: Authority email metadata. Accepted for reusing definitions; unused
          by the dispatcher., type: str}
      subject: {description: Authority subject metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: dict}
      basic_constraints: {description: Authority basic constraints metadata. Accepted for
          reusing definitions; unused by the dispatcher., type: list, elements: str}
      key_usage: {description: Authority key usage metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: list, elements: str}
      key_usage_critical: {description: Authority key usage critical metadata. Accepted for
          reusing definitions; unused by the dispatcher., type: bool}
      extended_key_usage: {description: Authority extended key usage metadata. Accepted for
          reusing definitions; unused by the dispatcher., type: list, elements: str}
      extended_key_usage_critical: {description: Authority extended key usage critical metadata.
          Accepted for reusing definitions; unused by the dispatcher., type: bool}
      san: {description: Authority san metadata. Accepted for reusing definitions; unused
          by the dispatcher., type: list, elements: str}
      san_critical: {description: Authority san critical metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: bool}
      aia_base_url: {description: Authority aia base url metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: str}
      cdp_base_url: {description: Authority cdp base url metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: str}
      raw_extensions: {description: Authority raw extensions metadata. Accepted for reusing
          definitions; unused by the dispatcher., type: list, elements: dict}
      pkinit: {description: Authority pkinit metadata. Accepted for reusing definitions; unused
          by the dispatcher., type: dict}
      days: {description: Authority days metadata. Accepted for reusing definitions; unused
          by the dispatcher., type: int}
      renewal: {description: Authority renewal metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: dict}
      digest:
        description: Authority digest metadata. Accepted for reusing definitions; unused by
          the dispatcher.
        type: str
        choices: [sha224, sha256, sha384, sha512]
      include_identifiers: {description: Authority include identifiers metadata. Accepted
          for reusing definitions; unused by the dispatcher., type: bool}
      key_mode: {description: Authority key mode metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: str}
      public_mode: {description: Authority public mode metadata. Accepted for reusing definitions;
          unused by the dispatcher., type: str}
      key_passphrase: {description: Current CA key password; also the fallback for archived
          keys. Protected by Ansible C(no_log)., type: str, required: true}
      certificate_policies: {description: Authority certificate policies metadata. Accepted
          for reusing definitions; unused by the dispatcher., type: list, elements: dict}
      policy_constraints: {description: Authority policy constraints metadata. Accepted for
          reusing definitions; unused by the dispatcher., type: dict}
      inhibit_any_policy: {description: Authority inhibit any policy metadata. Accepted for
          reusing definitions; unused by the dispatcher., type: raw}
      parent: {type: str, description: 'Parent name, used to identify a self-signed root.'}
      parent_key_passphrase: {type: str, description: 'Parent key password metadata, protected
          by Ansible C(no_log).'}
      default_days: {type: int, description: Default lifetime for certificates issued by this
          authority.}
      crl_days: {type: int, description: Number of days until CRL nextUpdate; required and
          positive., required: true}
      crl_renew_before_days: {type: float, description: 'Authority renewal window; overrides
          O(renew_before_days), including zero.'}
      crl_digest:
        type: str
        description: CRL signature digest for RSA and ECDSA; defaults to sha384.
        choices: [sha224, sha256, sha384, sha512]
      legacy_generation: {type: str, description: Optional generation ID owning the unsuffixed
          publication paths during migration.}
      archived_key_passphrases: {type: dict, description: 'Generation IDs mapped to archived
          key passwords. Ansible masks the entire mapping, including keys.'}
"""
