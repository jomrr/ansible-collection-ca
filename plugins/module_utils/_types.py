# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Key types accepted by the CA signing and export operations."""

from __future__ import annotations

try:
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    from cryptography.hazmat.primitives.asymmetric.types import (
        CertificatePublicKeyTypes,
    )

    PrivateKey = (
        rsa.RSAPrivateKey
        | ec.EllipticCurvePrivateKey
        | ed25519.Ed25519PrivateKey
        | ed448.Ed448PrivateKey
        | dsa.DSAPrivateKey
    )
    PublicKey = CertificatePublicKeyTypes
except ImportError:
    pass
