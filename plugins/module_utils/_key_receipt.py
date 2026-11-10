# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bind managed private-file bytes to a validated public key and their origin."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import Storage
from ansible_collections.jomrr.ca.plugins.module_utils._inventory_store import (
    read_json,
    record_path,
    write_json,
)


@dataclass(frozen=True)
class KeyReceipt:
    """Public identity and provenance of one exact private-key serialization."""

    public_key_sha256: str
    generated: bool


def _receipt_path(base_dir: str, path: str, content: bytes) -> str:
    """Restrict trust to files inside the managed CA, including archived copies."""
    if not base_dir or not Path(path).resolve().is_relative_to(
        Path(base_dir).resolve()
    ):
        return ""
    return record_path(base_dir, "keys", hashlib.sha256(content).hexdigest())


def key_receipt(base_dir: str, path: str, content: bytes) -> KeyReceipt | None:
    """Read evidence for these exact bytes; changed or foreign files have none."""
    receipt_path = _receipt_path(base_dir, path, content)
    if not receipt_path:
        return None
    try:
        record = read_json(receipt_path)
    except FileNotFoundError:
        return None
    fingerprint = record.get("public_key_sha256")
    generated = record.get("generated")
    if not isinstance(fingerprint, str) or not isinstance(generated, bool):
        raise TypeError(f"Invalid key receipt: {receipt_path}")
    return KeyReceipt(fingerprint, generated)


def store_key_receipt(
    path: str,
    content: bytes,
    receipt: KeyReceipt,
    storage: Storage,
    *,
    check_mode: bool = False,
) -> bool:
    """Remember generated or fully validated material without storing secrets."""
    receipt_path = _receipt_path(storage.base_dir, path, content)
    return bool(
        receipt_path
        and write_json(
            receipt_path,
            asdict(receipt),
            storage.attributes(private=True),
            check_mode=check_mode,
        )
    )
