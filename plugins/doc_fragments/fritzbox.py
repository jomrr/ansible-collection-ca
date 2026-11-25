# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Certificate definitions and credential-aware deployment settings."""

from dataclasses import dataclass


@dataclass
class ModuleDocFragment:
    """Certificate definitions and credential-aware deployment settings."""

    DOCUMENTATION = r"""
options:
  deploy:
    description: Explicit deployment settings. Supplied values override certificate.fritzbox_deploy
      and top-level settings.
    type: dict
    suboptions:
      enabled: {description: Deployment enable metadata; select hosts or tasks at the caller.,
        type: bool}
      url: {description: FRITZ!Box URL. HTTPS is required for idempotence comparison., type: str}
      username: {description: Login user., type: str}
      password: {description: 'Login password, protected by Ansible C(no_log).', type: str}
      timeout: {description: Network timeout in seconds., type: int}
      validate_certs: {description: Validate the current FRITZ!Box HTTPS certificate while
          connecting., type: bool}
      bundle_path: {description: Explicit FritzBox bundle path., type: path}
      force: {description: Upload even when the device certificate matches., type: bool}
  certificate:
    description: Optional source for output_dir and nested fritzbox_deploy. Complete or partial
      certificate definitions are accepted; issuance metadata is unused. Credential fields
      remain protected by Ansible C(no_log).
    type: dict
    suboptions:
      name: {description: 'Certificate metadata, unused by deployment.', type: str}
      issuer:
        description: Certificate issuer metadata, unused by deployment.
        version_added: 1.5.0
        type: str
      formats: {description: 'Certificate metadata, unused by deployment.', type: list, elements: str}
      bundle_key_format:
        description: Certificate metadata, unused by deployment.
        version_added: 1.3.0
        type: str
        choices: [pkcs8, traditional]
      key_type:
        description: Certificate metadata, unused by deployment.
        type: str
        choices: [RSA, ECDSA, P-256, P-384, Ed25519, Ed448, EC, P256, P384, ECDSA_P256, ECDSA_P384,
          EC_P256, EC_P384, prime256v1, secp256r1, secp384r1, ED25519, ED448, EdDSA25519,
          EdDSA448]
      key_size: {description: 'Certificate metadata, unused by deployment.', type: int}
      subject_ordered: {description: 'Certificate metadata, unused by deployment.', type: list,
        elements: dict}
      common_name: {description: 'Certificate metadata, unused by deployment.', type: str}
      email: {description: 'Certificate metadata, unused by deployment.', type: str}
      subject: {description: 'Certificate metadata, unused by deployment.', type: dict}
      basic_constraints: {description: 'Certificate metadata, unused by deployment.', type: list,
        elements: str}
      key_usage: {description: 'Certificate metadata, unused by deployment.', type: list,
        elements: str}
      key_usage_critical: {description: 'Certificate metadata, unused by deployment.', type: bool}
      extended_key_usage: {description: 'Certificate metadata, unused by deployment.', type: list,
        elements: str}
      extended_key_usage_critical: {description: 'Certificate metadata, unused by deployment.',
        type: bool}
      san: {description: 'Certificate metadata, unused by deployment.', type: list, elements: str}
      san_critical: {description: 'Certificate metadata, unused by deployment.', type: bool}
      aia_base_url: {description: 'Certificate metadata, unused by deployment.', type: str}
      cdp_base_url: {description: 'Certificate metadata, unused by deployment.', type: str}
      raw_extensions: {description: 'Certificate metadata, unused by deployment.', type: list,
        elements: dict}
      pkinit: {description: 'Certificate metadata, unused by deployment.', type: dict}
      days: {description: 'Certificate metadata, unused by deployment.', type: int}
      renewal: {description: 'Certificate metadata, unused by deployment.', type: dict}
      digest:
        description: Certificate metadata, unused by deployment.
        type: str
        choices: [sha224, sha256, sha384, sha512]
      include_identifiers: {description: 'Certificate metadata, unused by deployment.', type: bool}
      key_mode: {description: 'Certificate metadata, unused by deployment.', type: str}
      public_mode: {description: 'Certificate metadata, unused by deployment.', type: str}
      key_passphrase: {description: 'Certificate metadata, unused by deployment. Protected
          by Ansible C(no_log).', type: str}
      certificate_policies: {description: 'Certificate metadata, unused by deployment.', type: list,
        elements: dict}
      policy_constraints: {description: 'Certificate metadata, unused by deployment.', type: dict}
      inhibit_any_policy: {description: 'Certificate metadata, unused by deployment.', type: raw}
      type: {description: 'Certificate metadata, unused by deployment.', type: str}
      csr_path: {description: 'Certificate metadata, unused by deployment.', type: path}
      csr_content: {description: 'Certificate metadata, unused by deployment.', type: str}
      output_dir: {description: Certificate export directory; defaults to C(<base_dir>/certs/<name>).,
        type: path}
      directory_mode: {description: 'Certificate metadata, unused by deployment.', type: str}
      publish_private: {description: 'Certificate metadata, unused by deployment.', type: bool,
        default: false, version_added: 1.3.0}
      pfx_friendly_name:
        description: Certificate metadata, unused by deployment.
        type: str
        aliases: [friendly_name]
        version_added: 1.3.0
      pfx_encryption:
        description: Certificate metadata, unused by deployment.
        type: str
        choices: [best, compatibility2022]
        version_added: 1.3.0
      pfx_iterations: {description: 'Certificate metadata, unused by deployment.', type: int,
        version_added: 1.3.0}
      pfx_passphrase: {description: 'Certificate metadata, unused by deployment. Protected
          by Ansible C(no_log).', type: str}
      passphrase: {description: 'Certificate metadata, unused by deployment. Protected by
          Ansible C(no_log).', type: str}
      krb5_realm: {description: 'Certificate metadata, unused by deployment.', type: str}
      ad_object_guid: {description: 'Certificate metadata, unused by deployment.', type: str}
      fritzbox_deploy:
        description: Deployment settings; explicit deploy values take precedence.
        type: dict
        suboptions:
          enabled: {description: Deployment enable metadata; select hosts or tasks at the
              caller., type: bool}
          url: {description: FRITZ!Box URL. HTTPS is required for idempotence comparison.,
            type: str}
          username: {description: Login user., type: str}
          password: {description: 'Login password, protected by Ansible C(no_log).', type: str}
          timeout: {description: Network timeout in seconds., type: int}
          validate_certs: {description: Validate the current FRITZ!Box HTTPS certificate while
              connecting., type: bool}
          bundle_path: {description: Explicit FritzBox bundle path., type: path}
          force: {description: Upload even when the device certificate matches., type: bool}
"""
