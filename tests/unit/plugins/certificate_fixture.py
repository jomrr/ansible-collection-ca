# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared real CA state for issuance regression tests."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_engine import (
    single_certificate_argument_spec,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509 import (
    ca_authority_argument_spec,
    ensure_x509,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_chain import _ordered_chain
from ansible_collections.jomrr.ca.plugins.modules.authority import _authority_params
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class CertificateFixture:
    """Managed root and issuer with a key and CSR for external request tests."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.authority("root", "root")
        self.authority("issuer", "root")
        chain = _ordered_chain(str(self.base), "issuer")
        (self.base / "chains").mkdir()
        (self.base / "chains/issuer-ca-chain.pem").write_bytes(
            b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in chain)
        )
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OpenBao")])
            )
            .sign(self.key, hashes.SHA256())
        )

    def authority(self, name: str, parent: str, **overrides: Any) -> dict[str, Any]:
        """Create a managed CA using the module's real defaults and engine."""
        values = {
            key: spec.get("default")
            for key, spec in ca_authority_argument_spec().items()
        }
        values.update(
            base_dir=str(self.base),
            name=name,
            parent=parent,
            common_name=name,
            days=365,
            key_type="P-256",
            key_passphrase="test-passphrase",
            parent_key_passphrase="test-passphrase",
            owner=str(os.getuid()),
            group=str(os.getgid()),
            **overrides,
        )
        params, signed = _authority_params(values)
        return ensure_x509(params, signed=signed, authority=True)

    def request(self, issuer: str = "issuer") -> dict[str, Any]:
        """Build an external CA request with explicit certificate-signing usage."""
        params = {
            key: spec.get("default")
            for key, spec in single_certificate_argument_spec().items()
        }
        params.update(
            base_dir=str(self.base),
            owner=str(os.getuid()),
            group=str(os.getgid()),
            authorities=[
                {
                    "name": "root",
                    "parent": "root",
                    "key_passphrase": "test-passphrase",
                    "default_days": 90,
                },
                {
                    "name": "issuer",
                    "parent": "root",
                    "key_passphrase": "test-passphrase",
                    "default_days": 90,
                },
            ],
            certificate_types={"tls_server": {"issuer": issuer}},
            certificate={
                "name": "openbao",
                "common_name": "OpenBao",
                "type": "tls_server",
                "formats": ["pem"],
                "csr_content": self.csr.public_bytes(
                    serialization.Encoding.PEM
                ).decode(),
                "basic_constraints": ["CA:TRUE", "pathlen:0"],
                "key_usage": ["keyCertSign", "cRLSign"],
            },
        )
        return params
