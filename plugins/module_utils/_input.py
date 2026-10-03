# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validation at external mapping boundaries, without unchecked type assertions."""

from __future__ import annotations

from collections.abc import Mapping


def mapping(value: object, context: str) -> dict[str, object]:
    """Accept string-keyed mappings, rejecting malformed external records."""
    if not isinstance(value, Mapping):
        raise TypeError(f"{context} must be a dictionary")
    result: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise TypeError(f"{context} keys must be strings")
        result[key] = item
    return result


class InputValues:
    """Validate fields from Ansible or normalized dispatch input once."""

    def __init__(self, values: Mapping[str, object]) -> None:
        self.values = values

    def text(self, key: str, default: str = "") -> str:
        """Read text; None means an omitted optional input."""
        value = self.values.get(key)
        if value is None:
            return default
        if not isinstance(value, str):
            raise TypeError(f"{key} must be a string")
        return value

    def integer(self, key: str, default: int = 0) -> int:
        """Read an integer without silently accepting boolean values."""
        value = self.values.get(key)
        if value is None:
            return default
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{key} must be an integer")
        return value

    def boolean(self, key: str, default: bool = False) -> bool:
        """Read a normalized boolean."""
        value = self.values.get(key)
        if value is None:
            return default
        if not isinstance(value, bool):
            raise TypeError(f"{key} must be a boolean")
        return value

    def number(self, key: str, default: float = 0) -> float:
        """Read a number, retaining fractional CRL renewal windows."""
        value = self.values.get(key)
        if value is None:
            return default
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError(f"{key} must be a number")
        return float(value)

    def sequence(self, key: str) -> list[object]:
        """Read a list while retaining element validation at its owner."""
        value = self.values.get(key)
        if value is None:
            return []
        if not isinstance(value, list):
            raise TypeError(f"{key} must be a list")
        return list(value)

    def strings(self, key: str) -> list[str]:
        """Validate a string list without accepting nested structures."""
        result = []
        for item in self.sequence(key):
            if not isinstance(item, str):
                raise TypeError(f"{key} entries must be strings")
            result.append(item)
        return result

    def dictionary(self, key: str) -> dict[str, object]:
        """Read an optional nested mapping."""
        value = self.values.get(key)
        return {} if value is None else mapping(value, key)

    def text_mapping(self, key: str) -> dict[str, str]:
        """Read variable string keys with validated string values."""
        values = self.dictionary(key)
        return {name: InputValues(values).text(name) for name in values}
