# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build certificate definitions from inventory hosts and their overrides."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from ipaddress import ip_address
from typing import TypedDict, Unpack

from ansible.errors import AnsibleFilterError
from ansible.plugins import AnsiblePlugin
from ansible_collections.jomrr.ca.plugins.module_utils._input import mapping

DOCUMENTATION = r"""
name: host_certificates
short_description: Build certificate definitions from inventory hosts
version_added: 1.3.0
description:
- Return one certificate definition per distinct host, sorted by its resulting name.
  The default type is C(tls_server).
- The default common name is the host variable selected by O(fqdn_var), falling back to C(host.domain).
  Automatic SANs contain that DNS name, the input host
  name and the IPv4 or IPv6 address from C(hostvars[host].ansible_host), in that order.
- Since version 1.4.0, the host variable selected by O(overrides_var) can override certificate
  fields. Its C(san) list extends the automatic SANs, retaining order and removing
  duplicates. Other values replace defaults, including entire lists and dictionaries.
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
    - Optional C(fqdn), or the variable selected by O(fqdn_var), supplies the host's DNS name, including its domain.
    - Optional C(ca_certificate), or the variable selected by O(overrides_var), is a dictionary of certificate module options.
      Overrides of C(common_name) do not change the automatic DNS SANs derived from
      the selected FQDN or C(host.domain). Additional options are validated by the certificate modules.
    - A C(name) in the selected override dictionary renames the definition;
      duplicate resulting names raise an error.
    type: dict
    required: true
  domain:
    description: Fallback domain appended to hosts without the variable selected by O(fqdn_var).
      May be omitted when every selected host has that variable.
    type: str
  key_type:
    description: Key type copied into each definition for the certificate module.
    type: str
    default: P-384
  formats:
    description: Export formats copied into each definition for the certificate module.
    type: list
    elements: str
    default: [pem, der, txt, fullchain]
  fqdn_var:
    description: Host-variable name supplying the FQDN. This keyword-only option
      selects an exact variable name, not a dotted path or expression.
    type: str
    default: fqdn
    version_added: 1.4.0
  overrides_var:
    description: Host-variable name containing certificate overrides. This keyword-only
      option selects an exact variable name, not a dotted path or expression.
    type: str
    default: ca_certificate
    version_added: 1.4.0
"""

EXAMPLES = r"""
ca_certificates: >-
  {{ groups['webservers'] |
     jomrr.ca.host_certificates(hostvars, 'example.test') }}

custom_certificates: >-
  {{ groups['webservers'] | jomrr.ca.host_certificates(
       hostvars, 'example.test', key_type='P-256', formats=['pem', 'bundle']) }}

selected_host_variables: >-
  {{ groups['webservers'] | jomrr.ca.host_certificates(
       hostvars, 'example.test', fqdn_var='inventory_fqdn',
       overrides_var='pki_certificate') }}

# host_vars/web02.yml
ansible_host: 192.0.2.20
fqdn: web02.other.test
ca_certificate:
  type: tls_client
  key_type: RSA
  key_size: 3072
  san: [DNS:alias.other.test]
  formats: [pem, bundle]
"""

RETURN = r"""
_value:
  description:
  - Certificate definitions sorted by name, suitable for
    O(jomrr.ca.certificate#module:certificate) or
    O(jomrr.ca.certificate_batch#module:certificates).
  - Each definition contains C(name), C(type), C(common_name), C(key_type),
    C(san) and C(formats), plus additional options from the selected override dictionary.
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
    """Known defaults before merging the open certificate-module option mapping."""

    name: str
    type: str
    common_name: str
    key_type: str
    san: list[str]
    formats: list[str]


class HostVariableOptions(TypedDict, total=False):
    """Named keyword inputs for selecting inventory fields, validated at runtime."""

    fqdn_var: object
    overrides_var: object


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


def _text(value: object, label: str) -> str:
    """Validate non-empty text without changing its spelling or template tags."""
    if not isinstance(value, str) or not value.strip():
        raise AnsibleFilterError(f"{label} must be a non-empty string")
    return value


def _variable_names(options: HostVariableOptions) -> tuple[str, str]:
    """Validate named selectors while rejecting misspelled keyword options."""
    unknown = options.keys() - {"fqdn_var", "overrides_var"}
    if unknown:
        raise AnsibleFilterError(
            f"Unknown host_certificates options: {', '.join(sorted(unknown))}"
        )
    return (
        _text(options.get("fqdn_var", "fqdn"), "fqdn_var"),
        _text(options.get("overrides_var", "ca_certificate"), "overrides_var"),
    )


def _host_fqdn(
    variables: Mapping[str, object], host: str, domain: str | None, fqdn_var: str
) -> str:
    """Use an explicit DNS name or the caller's fallback domain."""
    if fqdn_var in variables:
        return _text(variables[fqdn_var], f"hostvars[{host!r}].{fqdn_var}")
    if domain is None:
        raise AnsibleFilterError(
            f"Host {host!r} requires {fqdn_var} or a fallback domain"
        )
    return f"{host}.{domain}"


def _host_address(variables: Mapping[str, object], host: str) -> str:
    """Read only the selected host's address and preserve lazy Ansible errors."""
    address = variables.get("ansible_host")
    message = f"hostvars[{host!r}].ansible_host must be an IPv4 or IPv6 address"
    if not isinstance(address, str):
        raise AnsibleFilterError(message)
    try:
        ip_address(address)
    except ValueError as exc:
        raise AnsibleFilterError(message) from exc
    return address


def _with_overrides(
    defaults: HostCertificate, overrides: object, host: str, overrides_var: str
) -> dict[str, object]:
    """Merge host options at the module-input boundary; copy mutable values."""
    context = f"hostvars[{host!r}].{overrides_var}"
    try:
        custom = deepcopy(mapping(overrides, context))
    except TypeError as exc:
        raise AnsibleFilterError(str(exc)) from exc
    result: dict[str, object] = {**defaults, **custom}
    for field in ("type", "common_name", "key_type"):
        result[field] = _text(result[field], f"{context}.{field}")
    result["formats"] = _strings(result["formats"], f"{context}.formats")
    result["san"] = list(
        dict.fromkeys(
            defaults["san"] + _strings(custom.get("san", []), f"{context}.san")
        )
    )
    return result


def host_certificates(
    hosts: object,
    hostvars: object,
    domain: object = None,
    key_type: object = "P-384",
    formats: object = None,
    **options: Unpack[HostVariableOptions],
) -> list[dict[str, object]]:
    """Return deterministic certificate definitions without mutating inventory data."""
    fqdn_var, overrides_var = _variable_names(options)
    if not isinstance(hostvars, Mapping):
        raise AnsibleFilterError("hostvars must be a mapping")
    if domain is not None:
        domain = _text(domain, "domain")
    key_type = _text(key_type, "key_type")
    export_formats = _strings(
        ("pem", "der", "txt", "fullchain") if formats is None else formats, "formats"
    )
    result: dict[str, dict[str, object]] = {}
    for host in sorted(set(_strings(hosts, "hosts"))):
        variables = hostvars.get(host)
        if not isinstance(variables, Mapping):
            raise AnsibleFilterError(f"hostvars[{host!r}] must be a mapping")
        common_name = _host_fqdn(variables, host, domain, fqdn_var)
        definition = _with_overrides(
            HostCertificate(
                name=host,
                type="tls_server",
                common_name=common_name,
                key_type=key_type,
                san=[
                    f"DNS:{common_name}",
                    f"DNS:{host}",
                    f"IP:{_host_address(variables, host)}",
                ],
                formats=export_formats.copy(),
            ),
            variables.get(overrides_var, {}),
            host,
            overrides_var,
        )
        name = _text(definition["name"], f"hostvars[{host!r}].{overrides_var}.name")
        if name in result:
            raise AnsibleFilterError(f"Duplicate certificate name {name!r}")
        result[name] = definition
    return [result[name] for name in sorted(result)]


class FilterModule(AnsiblePlugin):
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., list[dict[str, object]]]]:
        """Expose the documented filter name through Ansible's loader."""
        return {"host_certificates": host_certificates}
