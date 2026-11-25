# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify issuer selection using signatures rather than issuer subject names."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography import x509


def main() -> None:
    """Inspect the two issued certificates, exported chains and inventory."""
    base = Path(sys.argv[1])
    authorities = {
        name: x509.load_pem_x509_certificate((base / f"ca/{name}-ca.pem").read_bytes())
        for name in ("primary", "secondary")
    }
    assert authorities["primary"].subject == authorities["secondary"].subject
    assert authorities["primary"].public_key() != authorities["secondary"].public_key()
    inventory = json.loads((base / "inventory/ca-inventory.json").read_text())
    records = {item["name"]: item for item in inventory["certificates"]}
    for name, issuer, days in (
        ("default-server", "primary", 30),
        ("override-server", "secondary", 60),
    ):
        directory = base / "certs" / name
        certificate = x509.load_pem_x509_certificate(
            (directory / f"{name}.pem").read_bytes()
        )
        certificate.verify_directly_issued_by(authorities[issuer])
        assert (
            certificate.not_valid_after_utc - certificate.not_valid_before_utc
        ).days == days
        assert x509.load_pem_x509_certificates(
            (directory / f"{name}-chain.pem").read_bytes()
        ) == [authorities[issuer]]
        assert x509.load_pem_x509_certificates(
            (directory / f"{name}-fullchain.pem").read_bytes()
        ) == [certificate, authorities[issuer]]
        assert records[name]["issuer"] == issuer
    print("Verified type default and explicit issuer signatures, chains and lifetimes")


if __name__ == "__main__":
    main()
