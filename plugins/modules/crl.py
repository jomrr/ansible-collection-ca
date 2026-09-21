# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Manage CA collection certificate revocation lists."""

from __future__ import annotations

DOCUMENTATION = r"""
module: crl
short_description: Manage CA collection certificate revocation lists
version_added: 0.1.0
description:
- Manage CA collection certificate revocation lists.
extends_documentation_fragment: [jomrr.ca.context, jomrr.ca.context.ownership, jomrr.ca.context.publishing,
  jomrr.ca.context.digest, jomrr.ca.context.formats, jomrr.ca.context.file_mode, jomrr.ca.context.cryptography]
options:
  name:
    description: Authority short name used to locate its certificate and private key.
    version_added: 0.1.0
    type: str
    required: true
  key_passphrase:
    description: Passphrase for the CA private key.
    version_added: 0.1.0
    type: str
    required: true
  common_name:
    description: CA subject Common Name.
    version_added: 0.1.0
    type: str
    required: true
  subject:
    description: Subject defaults for the CRL issuer name.
    version_added: 0.1.0
    type: dict
    default: {}
  next_update_days:
    description: Number of days until CRL C(nextUpdate).
    version_added: 0.1.0
    type: int
    required: true
  renew_before_days:
    description: Renew this many days before CRL expiry; must be less than next_update_days.
    version_added: 0.1.0
    type: float
    default: 7
  revoked_certificates:
    description: Declarative revoked certificate entries.
    version_added: 0.1.0
    type: list
    default: []
    elements: dict
  base_url:
    description: Stored in composed inventory when C(ca_name) is set.
  digest:
    description: Signature digest for RSA and ECDSA CA keys.
  formats:
    description: CRL output formats written from one generated CRL object.
    default: [pem, der]
  mode:
    description: CRL file mode.
"""

EXAMPLES = r"""
- name: Create component CA CRL
  jomrr.ca.crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    common_name: Example Component CA
    subject: {country: DE, organization: Example, organizational_unit: Example PKI}
    next_update_days: 7
    renew_before_days: 1
    key_passphrase: "{{ ca_component_passphrase }}"

- name: Create component CA CRLs
  jomrr.ca.crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    common_name: Example Component CA
    next_update_days: 7
    renew_before_days: 1
    key_passphrase: "{{ ca_component_passphrase }}"
    revoked_certificates:
      - name: web01
        reason: key_compromise
        invalidity_date: "2026-06-14T00:00:00Z"

- name: Create component CA CRLs with fingerprint revocation
  jomrr.ca.crl:
    base_dir: /etc/pki/example
    ca_name: example
    name: component
    common_name: Example Component CA
    next_update_days: 7
    renew_before_days: 1
    key_passphrase: "{{ ca_component_passphrase }}"
    revoked_certificates:
      - sha256: "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        reason: superseded
"""

RETURN = r"""
inventory_changed:
  description: Whether inventory state changed.
  type: bool
  returned: success
paths:
  description: Output paths keyed by format.
  type: dict
  returned: success
crl_number:
  description: CRL Number extension value.
  type: int
  returned: success
formats:
  description: Normalized CRL output formats.
  type: list
  elements: str
  returned: success
"""

# Ansible requires DOCUMENTATION, EXAMPLES and RETURN before normal imports.
# pylint: disable=wrong-import-position
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from ansible.module_utils.basic import (
    AnsibleModule,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl import (
    _build_crl,
    _desired_authority_key_identifier,
    _desired_revoked,
    _existing_numbers,
    _load_existing_crls,
    _needs_rebuild,
    _signature_algorithm_oid,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl_state import (
    last_crl_number,
    store_crl_number,
)
from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    OPERATION_ERRORS,
    require_cryptography,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    FileAttributes,
    ca_lock_path,
    file_argument_spec,
    file_locks,
    sanitize_error,
    write_file,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory import (
    resolve_revocation_entries,
    update_crl_inventory,
)
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_summary import (
    _crl_number,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509 import (
    load_certificate,
    load_private_key,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import DIGESTS

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass

# pylint: enable=wrong-import-position


SUPPORTED_FORMATS = {"pem", "der"}


def _formats(value: Any) -> list[str]:
    """Return normalized CRL output formats."""
    if isinstance(value, str):
        raise TypeError("formats must be a list")
    formats = [str(item).lower() for item in (value or ["pem", "der"])]
    unsupported = sorted(set(formats).difference(SUPPORTED_FORMATS))
    if unsupported:
        raise ValueError(f"Unsupported CRL formats: {', '.join(unsupported)}")
    return formats


def _with_derived_paths(params: dict[str, Any]) -> dict[str, Any]:
    """Derive CRL and CA private key paths from base parameters."""
    result = dict(params)
    base_dir = str(result["base_dir"]).rstrip("/")
    name = str(result["name"])
    result["formats"] = _formats(result.get("formats"))
    result["paths"] = {
        "pem": f"{base_dir}/crl/{name}-ca.crl.pem",
        "der": f"{base_dir}/crl/{name}-ca.crl",
    }
    result["paths"] = {
        crl_format: path
        for crl_format, path in result["paths"].items()
        if crl_format in result["formats"]
    }
    result["privatekey_path"] = f"{base_dir}/private/{name}-ca.key"
    result["certificate_path"] = f"{base_dir}/ca/{name}-ca.pem"
    return result


def _write_crls(params: dict[str, Any], crl: x509.CertificateRevocationList) -> bool:
    """Write one CRL object to all requested output formats."""
    changed = False
    for crl_format, path in params["paths"].items():
        encoding = (
            serialization.Encoding.DER
            if crl_format == "der"
            else serialization.Encoding.PEM
        )
        changed = (
            write_file(
                path,
                crl.public_bytes(encoding),
                FileAttributes.from_params(params, "mode"),
                force=params["force"],
            )
            or changed
        )
    return changed


def run_module() -> None:
    """Run the Ansible module for certificate revocation lists."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "base_url": {"type": "str", "default": ""},
            "ca_name": {"type": "str", "default": ""},
            "name": {"type": "str", "required": True},
            "formats": {
                "type": "list",
                "elements": "str",
                "default": ["pem", "der"],
            },
            "key_passphrase": {"type": "str", "required": True, "no_log": True},
            "common_name": {"type": "str", "required": True},
            "subject": {"type": "dict", "default": {}},
            "next_update_days": {"type": "int", "required": True},
            "renew_before_days": {"type": "float", "default": 7},
            "revoked_certificates": {"type": "list", "elements": "dict", "default": []},
            "digest": {"type": "str", "default": "sha384", "choices": list(DIGESTS)},
            **file_argument_spec(),
        },
        supports_check_mode=False,
    )

    require_cryptography(module)

    params = _with_derived_paths(module.params)
    inventory_changed = False
    try:
        if not 0 <= params["renew_before_days"] < params["next_update_days"]:
            raise ValueError(
                "renew_before_days must be nonnegative and less than next_update_days"
            )
        with file_locks(
            [
                ca_lock_path(params["base_dir"], "authority", params["name"]),
                ca_lock_path(params["base_dir"], "crl", params["name"]),
            ]
        ):
            params["revoked_certificates"] = resolve_revocation_entries(
                base_dir=str(params["base_dir"]),
                authority=str(params["name"]),
                entries=params["revoked_certificates"],
            )
            ca_cert = load_certificate(params["certificate_path"])
            existing_crls = _load_existing_crls(params["paths"])
            existing_numbers = _existing_numbers(existing_crls)
            previous_number = last_crl_number(params["base_dir"], params["name"])
            if not previous_number and any(
                Path(path).exists() for path in params["paths"].values()
            ):
                raise ValueError(
                    "CRL exports exist but their sequence state is missing"
                )
            if any(number > previous_number for number in existing_numbers):
                raise ValueError("CRL export number exceeds the persistent sequence")
            desired_signature_algorithm = _signature_algorithm_oid(
                ca_cert, params["digest"]
            )
            desired_revoked = _desired_revoked(params["revoked_certificates"])
            changed = (
                params["force"]
                or previous_number > max(existing_numbers or [0])
                or _needs_rebuild(
                    existing_crls=existing_crls,
                    params=params,
                    desired_signature_algorithm=desired_signature_algorithm,
                    desired_revoked=desired_revoked,
                    desired_authority_key=_desired_authority_key_identifier(ca_cert),
                )
            )
            if changed:
                private_key = load_private_key(
                    params["privatekey_path"],
                    params["key_passphrase"],
                )
                crl_number = previous_number + 1
                crl = _build_crl(
                    params,
                    crl_number=crl_number,
                    ca_cert=ca_cert,
                    private_key=private_key,
                )
            else:
                crl = next(crl for crl in existing_crls.values() if crl is not None)
                existing_crl_number = _crl_number(crl)
                if existing_crl_number is None:
                    raise ValueError("existing CRL is missing a CRL Number")
                crl_number = existing_crl_number

            changed = store_crl_number(params, crl_number) or changed
            inventory_changed = update_crl_inventory(params, crl)
            changed = _write_crls(params, crl) or changed
            changed = changed or inventory_changed
    except OPERATION_ERRORS as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))
    module.exit_json(
        changed=changed,
        inventory_changed=inventory_changed,
        formats=params["formats"],
        paths=params["paths"],
        crl_number=crl_number,
    )


def main() -> None:
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
