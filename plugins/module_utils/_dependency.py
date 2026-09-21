# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Optional cryptography dependency on the managed node."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule

crypto_errors: tuple[type[Exception], ...] = ()
CRYPTOGRAPHY_IMPORT_ERROR: str | None
try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

    crypto_errors = (
        UnsupportedAlgorithm,
        InvalidSignature,
        x509.DuplicateExtension,
        x509.InvalidVersion,
    )
except ImportError as exc:
    CRYPTOGRAPHY_IMPORT_ERROR = str(exc)
else:
    CRYPTOGRAPHY_IMPORT_ERROR = None


MATERIAL_ERRORS = (OSError, ValueError, TypeError) + crypto_errors
OPERATION_ERRORS = MATERIAL_ERRORS + (KeyError, RuntimeError)


def require_cryptography(module: AnsibleModule) -> None:
    """Fail through Ansible when the managed interpreter lacks cryptography."""
    if CRYPTOGRAPHY_IMPORT_ERROR is not None:
        module.fail_json(
            msg=f"Failed to import cryptography: {CRYPTOGRAPHY_IMPORT_ERROR}"
        )
