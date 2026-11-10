# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only batch certificate orchestration."""

from __future__ import annotations

from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_results import (
    CertificateResult,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509 import (
    ensure_x509_operations,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_params import (
    with_derived_paths,
)


def preview_certificates(values: list[dict[str, Any]]) -> list[CertificateResult]:
    """Hold existing locks while predicting each certificate without mutation."""
    operations = [
        with_derived_paths(
            item, signed=True, authority=False, manage_directory=True, manage_chain=True
        )
        for item in values
    ]
    for operation in operations:
        operation.check_mode = True
    return ensure_x509_operations(operations, manage_directory=True, manage_chain=True)
