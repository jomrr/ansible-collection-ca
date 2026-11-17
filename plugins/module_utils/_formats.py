# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Internal normalization and validation of artifact output formats."""

from __future__ import annotations

from collections.abc import Collection, Sequence
from typing import Any

DEFAULT_PUBLIC_FORMATS = ("pem", "der", "txt")
CERTIFICATE_DEFAULT_FORMATS: dict[str, list[str]] = {
    "issuing_ca": [*DEFAULT_PUBLIC_FORMATS, "fullchain"],
    "tls_server": list(DEFAULT_PUBLIC_FORMATS),
    "tls_client": list(DEFAULT_PUBLIC_FORMATS),
    "eap_tls_client": list(DEFAULT_PUBLIC_FORMATS),
    "mskdc": list(DEFAULT_PUBLIC_FORMATS),
    "identity": [*DEFAULT_PUBLIC_FORMATS, "pfx"],
    "identity_full": [*DEFAULT_PUBLIC_FORMATS, "pfx"],
    "fritzbox": [*DEFAULT_PUBLIC_FORMATS, "fritzbox"],
}
CERTIFICATE_SUPPORTED_FORMATS = {
    "pem",
    "der",
    "cer",
    "txt",
    "pfx",
    "p12",
    "fullchain",
    "bundle",
    "fritzbox",
}


def normalize_formats(
    value: Any,
    *,
    defaults: Sequence[str] = (),
    supported: Collection[str] | None = None,
    context: str = "certificate",
) -> list[str]:
    """Preserve format order and duplicates while applying caller-specific rules."""
    if isinstance(value, str):
        raise TypeError("formats must be a list")
    formats = [str(item).lower() for item in (value or defaults)]
    if supported is not None:
        unsupported = sorted(set(formats).difference(supported))
        if unsupported:
            raise ValueError(f"Unsupported {context} formats: {', '.join(unsupported)}")
    return formats
