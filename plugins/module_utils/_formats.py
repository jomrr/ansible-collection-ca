# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Internal normalization and validation of artifact output formats."""

from __future__ import annotations

from collections.abc import Collection, Sequence
from typing import Any


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
