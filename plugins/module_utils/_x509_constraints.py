# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Internal issuer authorization and path length checks before certificate issuance."""

from __future__ import annotations

from ansible_collections.jomrr.ca.plugins.module_utils._x509_extensions import (
    basic_constraints,
)

try:
    from cryptography import x509
except ImportError:
    pass


def validate_issuer_constraints(
    certificate_name: str,
    requested_constraints: list[str],
    subject: x509.Name,
    chain: list[x509.Certificate],
) -> None:
    """Require a usable issuer path, counting a requested CA as an intermediate.

    A newly issued CA must support leaf issuance beneath it. Self-issued CA
    certificates do not consume path length (RFC 5280, sections 4.2.1.9 and 6.1.4).
    A child's own pathlen never overrides a limit inherited from an ancestor.
    """
    requested = basic_constraints(requested_constraints)
    ca_below = int(requested.ca and subject != chain[0].subject)
    for issuer in chain:
        name = issuer.subject.rfc4514_string()
        try:
            constraints = issuer.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound as error:
            raise ValueError(f"Issuer {name} is missing Basic Constraints") from error
        if not constraints.ca:
            raise ValueError(f"Issuer {name} must have CA:TRUE")
        try:
            usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            usage = None
        if usage is not None and not usage.key_cert_sign:
            raise ValueError(f"Issuer {name} is missing keyCertSign")
        if constraints.path_length is not None and ca_below > constraints.path_length:
            raise ValueError(
                f"Cannot issue certificate {certificate_name}: issuer {name} "
                f"pathlen:{constraints.path_length} would be exceeded "
                f"({ca_below} non-self-issued intermediate CAs). "
                "Select an issuer whose complete CA chain permits this depth."
            )
        ca_below += int(issuer.subject != issuer.issuer)
