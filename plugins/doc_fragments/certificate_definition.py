# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Static nested certificate schemas for single and batch documentation."""

from dataclasses import dataclass


@dataclass
class ModuleDocFragment:
    """Ansible documentation fragments with statically readable values."""

    DOCUMENTATION = r"""
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
        description:
        - Requested export formats; omitted values use the selected profile defaults.
        - C(bundle) writes the leaf certificate, private key, then issuer intermediates to C(<name>-bundle.pem) with C(bundle_key_format=pkcs8).
          Excludes the self-signed root; unavailable for external CSRs. Uses C(key_mode), default C(0600).
        - C(bundle_key_format=traditional) retains the order of leaf certificate, issuer intermediates, then private key.
        - C(fritzbox) retains its existing order of leaf certificate, issuer intermediates, then original managed key.
        - C(cer) writes DER-encoded certificate bytes with a C(.cer) extension.
          C(der) and C(cer) can be requested together.
        type: list
        elements: str
      bundle_key_format:
        description:
        - Private key encoding for C(bundle) only; defaults to C(pkcs8).
        - C(traditional) uses algorithm-specific PEM for RSA or ECDSA; Ed25519 and Ed448 require C(pkcs8).
        - Encryption follows C(key_passphrase). Does not change the managed key or C(fritzbox) export.
        version_added: 1.3.0
        type: str
        choices: [pkcs8, traditional]
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
        description:
          - Extended Key Usage overrides. An empty list omits the extension.
          - When omitted, leaf certificates use the selected profile defaults.
            Certificates with C(CA:TRUE) have no automatic Extended Key Usage.
        type: list
        elements: str
      extended_key_usage_critical:
        description: Marks Extended Key Usage critical.
        type: bool
      san:
        description:
          - Approved Subject Alternative Name entries. CSR SANs are never inherited.
          - An empty list disables the automatic DNS SAN derived from C(common_name).
            Certificates with C(CA:TRUE) never receive that automatic DNS SAN.
          - The C(mskdc) profile still adds its required PKINIT SAN.
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
        description: Built-in certificate profile providing defaults, including the default issuer.
        type: str
        required: true
      issuer:
        description: Authority name overriding C(certificate_types[type].issuer) for this
          certificate. Applies to every profile. The name must exist in O(authorities).
          Omit or set to null to use the type default; an empty name is invalid.
        version_added: 1.5.0
        type: str
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
      publish_private:
        description:
        - Allow C(jomrr.ca.artifacts) to list this certificate's local key and
          requested private exports, marking them with C(secret=true).
        - Consumer metadata for devices whose private material an administrator
          handles manually. Does not create additional exports or publish files.
        type: bool
        default: false
        version_added: 1.3.0
      pfx_friendly_name:
        description: PKCS#12 friendly name; defaults to the common name or object name.
          The existing C(friendly_name) spelling remains an alias.
        type: str
        aliases: [friendly_name]
        version_added: 1.3.0
      pfx_encryption:
        description:
        - Encryption for C(pfx) and C(p12); defaults to C(best), the library's BestAvailableEncryption.
        - C(compatibility2022) selects PBES1 SHA-1 with 3-key TripleDES-CBC and a SHA-1 MAC
          for legacy devices. Select it only when the device requires these algorithms.
        type: str
        choices: [best, compatibility2022]
        version_added: 1.3.0
      pfx_iterations:
        description: Optional encryption KDF iteration count, from 1 to 2147483647.
          When omitted, new exports use the library default and existing iteration counts
          are accepted. Does not set the separate MAC iteration count.
        type: int
        version_added: 1.3.0
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
        description:
          - Optional AD object GUID for C(mskdc), in canonical GUID or raw 16-byte hexadecimal form.
          - When omitted or empty, the NTDS objectGUID extension C(1.3.6.1.4.1.311.25.1)
            is not added. Non-empty values must be valid GUIDs.
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
          bundle_path:
            description: Deployment bundle path, unused by the certificate dispatcher.
            type: path
          force:
            description: Deployment force flag, unused by the certificate dispatcher.
            type: bool
"""

    BATCH = r"""
options:
  certificates:
    description: Declarative certificate definition. Unknown fields are rejected; pass only
      the documented schema.
    type: list
    elements: dict
    required: true
    suboptions:
      name: {description: Managed object name used for files and inventory., type: str, required: true}
      formats:
        description: [Requested export formats; omitted values use the selected profile defaults.,
          'C(bundle) writes the leaf certificate, private key, then issuer intermediates to
            C(<name>-bundle.pem) with C(bundle_key_format=pkcs8). Excludes the self-signed
            root; unavailable for external CSRs. Uses C(key_mode), default C(0600).', 'C(bundle_key_format=traditional)
            retains the order of leaf certificate, issuer intermediates, then private key.',
          'C(fritzbox) retains its existing order of leaf certificate, issuer intermediates,
            then original managed key.', C(cer) writes DER-encoded certificate bytes with
            a C(.cer) extension. C(der) and C(cer) can be requested together.]
        type: list
        elements: str
      bundle_key_format:
        description: [Private key encoding for C(bundle) only; defaults to C(pkcs8)., C(traditional)
            uses algorithm-specific PEM for RSA or ECDSA; Ed25519 and Ed448 require C(pkcs8).,
          Encryption follows C(key_passphrase). Does not change the managed key or C(fritzbox)
            export.]
        version_added: 1.3.0
        type: str
        choices: [pkcs8, traditional]
      key_type:
        description: Private key algorithm.
        type: str
        choices: [RSA, ECDSA, P-256, P-384, Ed25519, Ed448, EC, P256, P384, ECDSA_P256, ECDSA_P384,
          EC_P256, EC_P384, prime256v1, secp256r1, secp384r1, ED25519, ED448, EdDSA25519,
          EdDSA448]
      key_size: {description: Key size or ECDSA curve selector. Ignored for Ed25519 and Ed448.,
        type: int}
      subject_ordered: {description: 'Full ordered subject override. Takes precedence over
          C(subject), C(common_name), and C(email).', type: list, elements: dict}
      common_name: {description: Common Name. Required unless C(subject_ordered) is set.,
        type: str}
      email: {description: Optional subject C(emailAddress)., type: str}
      subject: {description: Subject defaults used with C(common_name)., type: dict}
      basic_constraints: {description: Basic Constraints tokens., type: list, elements: str}
      key_usage: {description: Key Usage tokens., type: list, elements: str}
      key_usage_critical: {description: Marks Key Usage critical., type: bool}
      extended_key_usage:
        description: [Extended Key Usage overrides. An empty list omits the extension., 'When
            omitted, leaf certificates use the selected profile defaults. Certificates with
            C(CA:TRUE) have no automatic Extended Key Usage.']
        type: list
        elements: str
      extended_key_usage_critical: {description: Marks Extended Key Usage critical., type: bool}
      san:
        description: [Approved Subject Alternative Name entries. CSR SANs are never inherited.,
          'An empty list disables the automatic DNS SAN derived from C(common_name). Certificates
            with C(CA:TRUE) never receive that automatic DNS SAN.', The C(mskdc) profile still
            adds its required PKINIT SAN.]
        type: list
        elements: str
      san_critical: {description: Marks SAN critical., type: bool}
      aia_base_url: {description: 'Explicit AIA URL prefix. The module appends C(<parent>-ca.der)
          (the root name for a root), with a generation suffix after a key or subject change.',
        type: str}
      cdp_base_url: {description: 'Explicit CDP URL prefix. The module appends C(<parent>-ca.crl)
          (the root name for a root), with a generation suffix after a key or subject change.',
        type: str}
      raw_extensions: {description: Additional unrecognized extensions., type: list, elements: dict}
      pkinit: {description: Internal PKINIT context for SAN otherName encoding., type: dict}
      days: {description: Certificate lifetime in days; defaults to the selected authority
          C(default_days)., type: int}
      renewal: {description: Renewal and rekey policy., type: dict}
      digest:
        description: Signature digest; defaults to the selected profile digest.
        type: str
        choices: [sha224, sha256, sha384, sha512]
      include_identifiers: {description: Adds SKI and AKI extensions., type: bool}
      key_mode: {description: Private key file mode., type: str}
      public_mode: {description: 'CSR, certificate, DER, text, and inventory file mode.',
        type: str}
      key_passphrase: {description: 'Optional managed private key password, protected by Ansible
          C(no_log). Unused for external CSRs.', type: str}
      certificate_policies: {description: Certificate policies., type: list, elements: dict}
      policy_constraints: {description: Policy constraints., type: dict}
      inhibit_any_policy: {description: Inhibit any policy., type: raw}
      type: {description: 'Built-in certificate profile providing defaults, including the
          default issuer.', type: str, required: true}
      issuer:
        description: Authority name overriding C(certificate_types[type].issuer) for this
          certificate. Applies to every profile. The name must exist in O(authorities).
          Omit or set to null to use the type default; an empty name is invalid.
        version_added: 1.5.0
        type: str
      csr_path: {description: External PEM CSR path on the managed CA host; mutually exclusive
          with C(csr_content)., type: path}
      csr_content: {description: External PEM CSR content; mutually exclusive with C(csr_path).,
        type: str}
      output_dir: {description: Certificate export directory; defaults to C(<base_dir>/certs/<name>).,
        type: path}
      directory_mode: {description: Certificate directory permissions; defaults to C(0755).,
        type: str}
      publish_private:
        description: ['Allow C(jomrr.ca.artifacts) to list this certificate''s local key and
            requested private exports, marking them with C(secret=true).', Consumer metadata
            for devices whose private material an administrator handles manually. Does not
            create additional exports or publish files.]
        type: bool
        default: false
        version_added: 1.3.0
      pfx_friendly_name:
        description: PKCS#12 friendly name; defaults to the common name or object name. The
          existing C(friendly_name) spelling remains an alias.
        type: str
        aliases: [friendly_name]
        version_added: 1.3.0
      pfx_encryption:
        description: ['Encryption for C(pfx) and C(p12); defaults to C(best), the library''s
            BestAvailableEncryption.', C(compatibility2022) selects PBES1 SHA-1 with 3-key
            TripleDES-CBC and a SHA-1 MAC for legacy devices. Select it only when the device
            requires these algorithms.]
        type: str
        choices: [best, compatibility2022]
        version_added: 1.3.0
      pfx_iterations: {description: 'Optional encryption KDF iteration count, from 1 to 2147483647.
          When omitted, new exports use the library default and existing iteration counts
          are accepted. Does not set the separate MAC iteration count.', type: int, version_added: 1.3.0}
      pfx_passphrase: {description: PKCS#12 export password. Protected by Ansible C(no_log).,
        type: str}
      passphrase: {description: 'Alternate PKCS#12 password, taking precedence over C(pfx_passphrase).
          Protected by Ansible C(no_log).', type: str}
      krb5_realm: {description: PKINIT realm for C(mskdc); defaults to O(kerberos_realm).,
        type: str}
      ad_object_guid:
        description: ['Optional AD object GUID for C(mskdc), in canonical GUID or raw 16-byte
            hexadecimal form.', 'When omitted or empty, the NTDS objectGUID extension C(1.3.6.1.4.1.311.25.1)
            is not added. Non-empty values must be valid GUIDs.']
        type: str
      fritzbox_deploy:
        description: Optional deployment settings, accepted for reusing certificate definitions.
          Issuance does not deploy the certificate. Use M(jomrr.ca.fritzbox_deploy) separately.
        type: dict
        suboptions:
          enabled: {description: 'Deployment enable flag, unused by the certificate dispatcher.',
            type: bool}
          url: {description: 'Deployment endpoint, unused by the certificate dispatcher.',
            type: str}
          username: {description: 'Deployment user name, unused by the certificate dispatcher.',
            type: str}
          password: {description: 'Deployment password, protected by Ansible C(no_log).',
            type: str}
          timeout: {description: 'Deployment timeout, unused by the certificate dispatcher.',
            type: int}
          validate_certs: {description: 'Deployment TLS setting, unused by the certificate
              dispatcher.', type: bool}
          bundle_path: {description: 'Deployment bundle path, unused by the certificate dispatcher.',
            type: path}
          force: {description: 'Deployment force flag, unused by the certificate dispatcher.',
            type: bool}
"""
