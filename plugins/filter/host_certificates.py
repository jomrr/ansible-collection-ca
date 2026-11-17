# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build TLS server certificate definitions from inventory hosts."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from ipaddress import ip_address
from typing import TypedDict

from ansible.errors import AnsibleFilterError
from ansible.plugins import AnsiblePlugin

DOCUMENTATION = r"""
name: host_certificates
short_description: Build TLS server certificate definitions from inventory hosts
version_added: 1.3.0
description:
- Return one C(tls_server) certificate definition per distinct host, sorted by name.
- The common name is C(host.domain). SANs contain that DNS name, the input host
  name and the IPv4 or IPv6 address from C(hostvars[host].ansible_host), in that order.
- Runs on the controller without additional Python libraries or network lookups.
- Does not mutate the host list, host variables or formats.
author:
- Jonas Mauer (@jomrr)
positional: [hostvars, domain, key_type, formats]
options:
  _input:
    description: List of short inventory host names.
      An empty list returns an empty list.
    type: list
    elements: str
    required: true
  hostvars:
    description:
    - Inventory host variables indexed by host name.
    - Each selected host must have C(ansible_host) set to an IPv4 or IPv6 address.
      Missing hosts, missing addresses and non-IP addresses raise a filter error.
    type: dict
    required: true
  domain:
    description: Non-empty domain appended to every input host name with a dot.
    type: str
    required: true
  key_type:
    description: Key type copied into each definition for the certificate module.
    type: str
    default: P-384
  formats:
    description: Export formats copied into each definition for the certificate module.
    type: list
    elements: str
    default: [pem, der, txt, fullchain]
"""

EXAMPLES = r"""
ca_certificates: >-
  {{ groups['webservers'] |
     jomrr.ca.host_certificates(hostvars, 'example.test') }}

custom_certificates: >-
  {{ groups['webservers'] | jomrr.ca.host_certificates(
       hostvars, 'example.test', key_type='P-256', formats=['pem', 'bundle']) }}
"""

RETURN = r"""
_value:
  description:
  - Certificate definitions sorted by name, suitable for
    O(jomrr.ca.certificate#module:certificate) or
    O(jomrr.ca.certificate_batch#module:certificates).
  - Each definition contains C(name), C(type), C(common_name), C(key_type),
    C(san) and C(formats).
  type: list
  elements: dict
  sample:
  - name: web01
    type: tls_server
    common_name: web01.example.test
    key_type: P-384
    san: [DNS:web01.example.test, DNS:web01, 'IP:192.0.2.10']
    formats: [pem, der, txt, fullchain]
"""


class HostCertificate(TypedDict):
    """Public certificate definition produced for one inventory host."""

    name: str
    type: str
    common_name: str
    key_type: str
    san: list[str]
    formats: list[str]


def _strings(value: object, label: str) -> list[str]:
    """Validate a sequence without coercing values or changing their spelling."""
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise AnsibleFilterError(f"{label} must be a list of non-empty strings")
    result = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise AnsibleFilterError(f"{label} must be a list of non-empty strings")
        result.append(item)
    return result


def _host_address(hostvars: Mapping[str, object], host: str) -> str:
    """Read only the selected host's address and preserve lazy Ansible errors."""
    variables = hostvars.get(host)
    if not isinstance(variables, Mapping):
        raise AnsibleFilterError(f"hostvars[{host!r}] must be a mapping")
    address = variables.get("ansible_host")
    message = f"hostvars[{host!r}].ansible_host must be an IPv4 or IPv6 address"
    if not isinstance(address, str):
        raise AnsibleFilterError(message)
    try:
        ip_address(address)
    except ValueError as exc:
        raise AnsibleFilterError(message) from exc
    return address


def host_certificates(
    hosts: object,
    hostvars: object,
    domain: object,
    key_type: object = "P-384",
    formats: object = None,
) -> list[HostCertificate]:
    """Return deterministic certificate definitions without mutating inventory data."""
    names = _strings(hosts, "hosts")
    if not isinstance(hostvars, Mapping):
        raise AnsibleFilterError("hostvars must be a mapping")
    if not isinstance(domain, str) or not domain.strip():
        raise AnsibleFilterError("domain must be a non-empty string")
    if not isinstance(key_type, str) or not key_type.strip():
        raise AnsibleFilterError("key_type must be a non-empty string")
    export_formats = _strings(
        ("pem", "der", "txt", "fullchain") if formats is None else formats, "formats"
    )
    result: list[HostCertificate] = []
    for host in sorted(set(names)):
        common_name = f"{host}.{domain}"
        result.append(
            HostCertificate(
                name=host,
                type="tls_server",
                common_name=common_name,
                key_type=key_type,
                san=[
                    f"DNS:{common_name}",
                    f"DNS:{host}",
                    f"IP:{_host_address(hostvars, host)}",
                ],
                formats=export_formats.copy(),
            )
        )
    return result


class FilterModule(AnsiblePlugin):
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., list[HostCertificate]]]:
        """Expose the documented filter name through Ansible's loader."""
        return {"host_certificates": host_certificates}
