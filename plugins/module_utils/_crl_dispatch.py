# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared single-authority CRL schema, validation, locking and notifications."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._crl_engine import ensure_crls
from ansible_collections.jomrr.ca.plugins.module_utils._crl_models import CrlResult
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    ca_lock_path,
    file_argument_spec,
    file_locks,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import DIGESTS


def crl_argument_spec() -> dict[str, Any]:
    """Return the existing single-CRL argument contract."""
    return {
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
        "archived_key_passphrases": {"type": "dict", "default": {}, "no_log": True},
        "legacy_generation": {"type": "str", "default": ""},
        "common_name": {"type": "str"},
        "subject": {"type": "dict", "default": {}},
        "next_update_days": {"type": "int", "required": True},
        "renew_before_days": {"type": "float", "default": 7},
        "revoked_certificates": {"type": "list", "elements": "dict", "default": []},
        "digest": {"type": "str", "default": "sha384", "choices": list(DIGESTS)},
        **file_argument_spec(),
    }


def validate_crl_policy(params: dict[str, Any]) -> None:
    """Reject CRLs whose renewal window leaves no usable lifetime."""
    if not 0 <= params["renew_before_days"] < params["next_update_days"]:
        raise ValueError(
            "renew_before_days must be nonnegative and less than next_update_days"
        )


def ensure_authority_crls(
    params: dict[str, Any], *, warn: Callable[[str], None], check_mode: bool = False
) -> CrlResult:
    """Reconcile one authority under its existing authority and CRL locks."""
    validate_crl_policy(params)
    with file_locks(
        [
            ca_lock_path(params["base_dir"], "authority", params["name"]),
            ca_lock_path(params["base_dir"], "crl", params["name"]),
        ],
        readonly=check_mode,
    ):
        result = ensure_crls(params, check_mode=check_mode)
    if result["migration_conflicts"]:
        warn(
            f"Authority {params['name']}: Some certificates reference legacy URLs "
            "assigned to another generation; reissue or revoke those listed "
            "in migration_conflicts"
        )
    return result
