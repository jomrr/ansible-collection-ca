# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Internal lookup of current and archived inventory certificate material."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._paths import archive_directory
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    load_certificate,
)

try:
    from cryptography import x509
except ImportError:
    pass


def certificate_issuer(record: dict[str, Any]) -> str:
    """Return the signing authority of a leaf or managed CA inventory record."""
    return str(record.get("issuer", record.get("parent", "")))


def record_certificates(
    base_dir: str,
    record: dict[str, Any],
    *,
    archive_first: bool = False,
    archive_filename: str | None = None,
) -> Iterator[x509.Certificate]:
    """Load candidate material in the caller's order; callers verify its identity."""
    current = str(record.get("paths", {}).get("certificate_pem", ""))
    archived = Path(
        archive_directory(
            base_dir,
            record["name"],
            authority=record["record_type"] == "authority",
            serial=record["certificate"]["serial_number_hex"],
        )
    ) / (archive_filename if archive_filename is not None else Path(current).name)
    paths = [str(archived), current] if archive_first else [current, str(archived)]
    for path in paths:
        if not path:
            continue
        try:
            yield load_certificate(path)
        except FileNotFoundError:
            continue
