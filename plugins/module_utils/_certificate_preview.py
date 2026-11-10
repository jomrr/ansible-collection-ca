# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only batch certificate orchestration."""

from __future__ import annotations

from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_results import (
    CertificateResult,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import file_locks
from ansible_collections.jomrr.ca.plugins.module_utils._x509_params import (
    with_derived_paths,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_preview import preview_x509


def preview_certificates(values: list[dict[str, Any]]) -> list[CertificateResult]:
    """Hold existing locks while predicting each certificate without mutation."""
    operations = [
        with_derived_paths(
            item, signed=True, authority=False, manage_directory=True, manage_chain=True
        )
        for item in values
    ]
    locks = {
        path
        for operation in operations
        for path in (operation.paths["lock_path"], operation.paths["signer_lock_path"])
    }
    with file_locks(locks, readonly=True):
        return [
            preview_x509(
                operation, signed=True, manage_directory=True, manage_chain=True
            )
            for operation in operations
        ]
