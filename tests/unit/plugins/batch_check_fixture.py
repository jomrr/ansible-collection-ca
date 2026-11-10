# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe file state and reject mutation at operating-system boundaries."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import patch


def snapshot(root: Path) -> dict[str, tuple[bytes, int, int, int, int]]:
    """Capture content, modes, ownership and modification times, including locks."""
    return {
        str(path.relative_to(root)): (
            path.read_bytes() if path.is_file() else b"",
            path.stat().st_mode,
            path.stat().st_uid,
            path.stat().st_gid,
            path.stat().st_mtime_ns,
        )
        for path in root.rglob("*")
    }


@contextmanager
def forbid_mutation() -> Iterator[None]:
    """Reject filesystem mutation and cryptographic issuance during predictions."""
    original_open = os.open

    def read_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
            raise AssertionError(f"Check mode opened a file for writing: {path}")
        return original_open(path, flags, *args, **kwargs)

    with ExitStack() as stack:
        stack.enter_context(patch.object(os, "open", side_effect=read_open))
        for name in (
            "mkdir",
            "unlink",
            "replace",
            "rename",
            "chmod",
            "chown",
            "fchmod",
            "fchown",
        ):
            stack.enter_context(
                patch.object(
                    os, name, side_effect=AssertionError(f"Check mode called os.{name}")
                )
            )
        for target in (
            "cryptography.x509.CertificateBuilder.sign",
            "cryptography.x509.CertificateSigningRequestBuilder.sign",
            "cryptography.x509.CertificateRevocationListBuilder.sign",
            "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
            "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key",
        ):
            stack.enter_context(
                patch(
                    target,
                    side_effect=AssertionError(
                        "Check mode generated cryptographic material"
                    ),
                )
            )
        yield
