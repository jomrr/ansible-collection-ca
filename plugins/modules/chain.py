# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Manage an ordered PEM certificate chain on the managed host."""

from __future__ import annotations

DOCUMENTATION = r"""
module: chain
short_description: Manage an ordered PEM certificate chain on the managed host
version_added: 0.1.0
description:
- Manage an ordered PEM certificate chain on the managed host.
extends_documentation_fragment: [jomrr.ca.context, jomrr.ca.context.ownership, jomrr.ca.context.formats,
  jomrr.ca.context.file_mode, jomrr.ca.context.cryptography]
options:
  name:
    description: Authority short name. The module expects C(<base_dir>/ca/<name>-ca.pem).
    version_added: 0.1.0
    type: str
    required: true
  formats:
    description: Chain output formats.
"""

EXAMPLES = r"""
- name: Create component CA chain
  jomrr.ca.chain:
    base_dir: /etc/pki/example
    name: component
    owner: root
    group: root

- name: Normalize root CA chain state
  jomrr.ca.chain:
    base_dir: /etc/pki/example
    name: root
"""

RETURN = r"""
path:
  description: Derived stable PEM chain path.
  type: str
  returned: success
paths:
  description: Derived stable chain paths keyed by format.
  type: dict
  returned: success
state:
  description: C(present) for issuing CA chains, C(absent) for root CA chains.
  type: str
  returned: success
"""

# Ansible requires DOCUMENTATION, EXAMPLES and RETURN before normal imports.
# pylint: disable=wrong-import-position
from collections.abc import Callable
from pathlib import Path
from typing import cast

from ansible.module_utils.basic import AnsibleModule
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
from ansible_collections.jomrr.ca.plugins.module_utils._formats import (
    normalize_formats,
)
from ansible_collections.jomrr.ca.plugins.module_utils._paths import (
    authority_directory,
    chain_paths,
)
from ansible_collections.jomrr.ca.plugins.module_utils._text import certificate_text
from ansible_collections.jomrr.ca.plugins.module_utils._x509_chain import (
    _authority_name,
    _is_self_signed,
    _ordered_chain,
)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
except ImportError:
    pass

# pylint: enable=wrong-import-position


SUPPORTED_FORMATS = {"pem", "der", "txt"}


def _authority_lock_paths(base_dir: str, name: str) -> list[str]:
    """Return locks for the target authority and every readable CA certificate."""
    ca_dir = authority_directory(base_dir)
    authority_names = {_authority_name(path) for path in ca_dir.glob("*-ca.pem")}
    authority_names.add(name)
    return [
        ca_lock_path(base_dir, "authority", authority_name)
        for authority_name in authority_names
    ]


def _remove_file(path: str) -> bool:
    """Remove a managed file if it exists."""
    try:
        Path(path).unlink()
    except FileNotFoundError:
        return False
    return True


def _chain_content(certificates: list[x509.Certificate], chain_format: str) -> bytes:
    """Return normalized content for an ordered certificate chain."""
    if not certificates:
        raise ValueError("certificate chain needs at least one certificate")
    if chain_format == "pem":
        return b"".join(
            cert.public_bytes(serialization.Encoding.PEM).rstrip() + b"\n"
            for cert in certificates
        )
    if chain_format == "der":
        return b"".join(
            cert.public_bytes(serialization.Encoding.DER) for cert in certificates
        )
    if chain_format == "txt":
        return b"".join(
            certificate_text(cert).rstrip() + b"\n" for cert in certificates
        )
    raise ValueError(f"Unsupported CA chain format: {chain_format}")


def run_module() -> None:
    """Run the Ansible module for CA chain files."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "name": {"type": "str", "required": True},
            "formats": {
                "type": "list",
                "elements": "str",
                "default": ["pem", "der", "txt"],
            },
            **file_argument_spec(),
        },
        supports_check_mode=False,
    )

    require_cryptography(module)

    params = module.params
    try:
        formats = normalize_formats(
            params["formats"],
            defaults=("pem", "der", "txt"),
            supported=SUPPORTED_FORMATS,
            context="CA chain",
        )
        paths = chain_paths(params["base_dir"], params["name"], formats)
        with file_locks(
            [
                ca_lock_path(params["base_dir"], "authority", "__graph__"),
                *_authority_lock_paths(params["base_dir"], params["name"]),
            ]
        ):
            certificates = _ordered_chain(params["base_dir"], params["name"])
            if len(certificates) == 1 and _is_self_signed(certificates[0]):
                changed = False
                for path in paths.values():
                    changed = _remove_file(path) or changed
                state = "absent"
            else:
                changed = False
                for chain_format, path in paths.items():
                    content = _chain_content(certificates, chain_format)
                    changed = (
                        write_file(
                            path,
                            content,
                            FileAttributes.from_params(params, "mode"),
                            force=params["force"],
                        )
                        or changed
                    )
                state = "present"
    except OPERATION_ERRORS as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))

    module.exit_json(
        changed=changed,
        path=paths.get("pem", ""),
        paths=paths,
        state=state,
    )


def main() -> None:
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
