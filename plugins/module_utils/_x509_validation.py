# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate issuing relationships and derive publication identity before writes."""

from __future__ import annotations

from ansible_collections.jomrr.ca.plugins.module_utils._authority_generations import (
    issuer_urls,
)
from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    CertificateOperation,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_chain import ordered_chain
from ansible_collections.jomrr.ca.plugins.module_utils._x509_constraints import (
    validate_issuer_constraints,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_extensions import (
    subject_from_params,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_material import (
    validated_external_csr,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_policies import (
    validate_issuer_policies,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_state import SignerMaterial

try:
    from cryptography import x509
except ImportError:
    pass


def validate_signing_request(
    params: CertificateOperation, signer: SignerMaterial
) -> x509.CertificateSigningRequest | None:
    """Check the entire issuer path before writing any request material."""
    if not signer.issuer_chain:
        issuer = params.request["issuer"].name
        signer.issuer_chain = ordered_chain(params.request["storage"].base_dir, issuer)
    signer.cert = signer.issuer_chain[0]
    csr = validated_external_csr(params) if params.request["csr"].external else None
    subject = subject_from_params(params)
    validate_issuer_constraints(
        params.request["name"],
        params.request["extensions"].basic_constraints,
        subject,
        signer.issuer_chain,
    )
    validate_issuer_policies(params, signer.cert)
    issuer = params.request["issuer"].name
    params.urls = issuer_urls(
        params,
        issuer,
        signer.cert.subject,
        signer.cert.public_key(),
    )
    return csr
