# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Argument schemas for certificate dispatchers; no secret discovery at runtime."""

from __future__ import annotations

from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._x509_params import (
    ca_authority_argument_spec,
)


def certificate_options() -> dict[str, dict[str, Any]]:
    """Declare supported certificate fields without injecting profile defaults."""
    spec = ca_authority_argument_spec()
    # These values belong to the module context or resolved issuer, not the item.
    for name in (
        "base_dir",
        "base_url",
        "ca_name",
        "parent",
        "parent_key_passphrase",
        "owner",
        "group",
        "force",
    ):
        del spec[name]
    for option in spec.values():
        option.pop("default", None)
        option.pop("required", None)
    spec.update(
        {
            "type": {"type": "str", "required": True},
            "name": {"type": "str", "required": True},
            "csr_path": {"type": "path"},
            "csr_content": {"type": "str"},
            "output_dir": {"type": "path"},
            "directory_mode": {"type": "str"},
            "friendly_name": {"type": "str"},
            "pfx_passphrase": {"type": "str", "no_log": True},
            "passphrase": {"type": "str", "no_log": True},
            "krb5_realm": {"type": "str"},
            "ad_object_guid": {"type": "str"},
            "fritzbox_deploy": {
                "type": "dict",
                "options": {
                    "enabled": {"type": "bool"},
                    "url": {"type": "str"},
                    "username": {"type": "str"},
                    "password": {"type": "str", "no_log": True},
                    "timeout": {"type": "int"},
                    "validate_certs": {"type": "bool"},
                },
            },
        }
    )
    return spec


def authority_options() -> dict[str, dict[str, Any]]:
    """Accept authority definitions while protecting declared credential fields."""
    spec = ca_authority_argument_spec()
    for name in ("base_dir", "base_url", "ca_name", "owner", "group", "force"):
        del spec[name]
    for option in spec.values():
        option.pop("default", None)
        option.pop("required", None)
    spec.update(
        {
            "name": {"type": "str", "required": True},
            "key_passphrase": {"type": "str", "required": True, "no_log": True},
            "default_days": {"type": "int"},
            "crl_days": {"type": "int"},
            "crl_renew_before_days": {"type": "float"},
            "crl_digest": {"type": "str"},
            "legacy_generation": {"type": "str"},
            "archived_key_passphrases": {"type": "dict", "no_log": True},
        }
    )
    return spec
