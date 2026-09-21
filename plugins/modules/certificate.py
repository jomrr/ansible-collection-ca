# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Dispatch one managed CA collection certificate to the built-in X.509 profiles."""

from __future__ import annotations

DOCUMENTATION = r"""
module: certificate
short_description: Dispatch one managed CA collection certificate to the built-in X.509
  profiles
version_added: 0.1.0
description:
- Dispatch one managed CA collection certificate to the built-in X.509 profiles.
extends_documentation_fragment: [jomrr.ca.context, jomrr.ca.context.ownership, jomrr.ca.context.publishing,
  jomrr.ca.context.cryptography, jomrr.ca.context.dispatch_notes, jomrr.ca.certificate]
options:
  subject:
    description: Certificate-local subject values merged over module C(subject).
    version_added: 0.1.0
    type: dict
    default: {}
  renewal:
    description: Certificate-local renewal and rekey policy.
    version_added: 0.1.0
    type: dict
    default: {}
  certificate:
    description: Declarative certificate item.
    version_added: 0.1.0
    type: dict
    required: true
  base_url:
    description: Base publication URL. If set, AIA defaults to C(<base_url>/aia/<issuer>-ca.der)
      and CDP to C(<base_url>/crl/<issuer>-ca.crl).
"""

EXAMPLES = r"""
- name: Issue web certificate
  jomrr.ca.certificate:
    base_dir: /etc/pki/example
    ca_name: example
    base_url: http://pki.example.test
    certificate:
      name: web01
      type: tls_server
      common_name: web01.example.test
      san:
        - DNS:web01.example.test
        - DNS:web01
    certificate_types:
      tls_server:
        issuer: component
    authorities:
      - name: root
        parent: root
        key_passphrase: "{{ ca_root_passphrase }}"
        default_days: 3650
      - name: component
        parent: root
        key_passphrase: "{{ ca_component_passphrase }}"
        default_days: 397

- name: Issue identity certificate
  jomrr.ca.certificate:
    base_dir: /etc/pki/example
    ca_name: example
    certificate:
      name: alice
      type: identity
      common_name: Alice Example
      email: alice@example.test
      pfx_passphrase: "{{ alice_pfx_passphrase }}"
    certificate_types:
      identity:
        issuer: identity
    authorities: "{{ ca_authorities }}"

- name: Sign external web CSR
  jomrr.ca.certificate:
    base_dir: /etc/pki/example
    ca_name: example
    base_url: http://pki.example.test
    certificate:
      name: external-web01
      type: tls_server
      csr_path: /srv/pki/requests/external-web01.csr
      formats:
        - pem
        - der
        - txt
        - fullchain
    certificate_types:
      tls_server:
        issuer: component
    authorities: "{{ ca_authorities }}"

- name: Issue MSKDC certificate
  jomrr.ca.certificate:
    base_dir: /etc/pki/example
    ca_name: example
    kerberos_realm: EXAMPLE.TEST
    certificate:
      name: dc01
      type: mskdc
      common_name: dc01.example.test
      ad_object_guid: 8f2a02d1-862a-47cf-9a9b-6bda9c3bd2c5
    certificate_types:
      mskdc:
        issuer: component
        required_fields:
          - ad_object_guid
    authorities: "{{ ca_authorities }}"
"""

RETURN = r"""
name:
  description: Certificate name.
  type: str
  returned: success
profile:
  description: Resolved certificate profile.
  type: str
  returned: success
directory_changed:
  description: Whether the output directory changed.
  type: bool
  returned: success
chain_changed:
  description: Whether the issuer chain copy changed.
  type: bool
  returned: success
pkcs12_changed:
  description: Whether any PKCS#12 export changed.
  type: bool
  returned: success
fullchain_changed:
  description: Whether the fullchain bundle changed.
  type: bool
  returned: success
fritzbox_bundle_changed:
  description: Whether the FritzBox import bundle changed.
  type: bool
  returned: success
pkcs12_paths:
  description: Written PKCS#12 paths keyed by format.
  type: dict
  returned: success
fullchain_path:
  description: Fullchain bundle path, or empty string.
  type: str
  returned: success
fritzbox_bundle_path:
  description: FritzBox import bundle path, or empty string.
  type: str
  returned: success
formats:
  description: Normalized formats.
extends_documentation_fragment: [jomrr.ca.certificate]
"""

# Ansible requires DOCUMENTATION, EXAMPLES and RETURN before normal imports.
# pylint: disable=wrong-import-position
from collections.abc import Callable
from typing import cast

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_engine import (
    ensure_certificate_artifacts,
    single_certificate_argument_spec,
)
from ansible_collections.jomrr.ca.plugins.module_utils._module import (
    execute_certificate,
)

# pylint: enable=wrong-import-position


def run_module() -> None:
    """Run the Ansible module for dispatched certificate profiles."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec=single_certificate_argument_spec(),
        supports_check_mode=False,
    )

    execute_certificate(module, ensure_certificate_artifacts)


def main() -> None:
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
