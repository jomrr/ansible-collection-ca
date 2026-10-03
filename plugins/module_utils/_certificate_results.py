# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Typed issuance results and non-secret inventory metadata."""

from __future__ import annotations

from typing import NotRequired, TypedDict

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    RenewalDecision,
    RenewalPolicy,
)


class CertificateMetadata(TypedDict):
    """Resolved, public certificate information retained by the dispatcher."""

    name: str
    type: str
    common_name: str
    issuer: str
    days: int
    formats: list[str]
    output_dir: str
    renewal: RenewalPolicy
    csr_mode: bool


class MaterialChanges(TypedDict):
    """Changes recorded while managing one key/CSR/certificate generation."""

    directory_changed: bool
    archive_changed: bool
    key_changed: bool
    csr_changed: bool
    cert_changed: bool
    generation_changed: NotRequired[bool]


class ExportChanges(TypedDict):
    """Changes and paths returned by certificate export writers."""

    der_changed: bool
    txt_changed: bool
    chain_changed: bool
    pkcs12_changed: bool
    fullchain_changed: bool
    fritzbox_bundle_changed: bool
    pkcs12_paths: dict[str, str]


class CertificateResult(MaterialChanges, ExportChanges):
    """Serializable result schema; optional fields belong to specific operations."""

    changed: bool
    formats: list[str]
    renewal: RenewalDecision
    csr_path: str
    cert_path: str
    txt_path: str
    fullchain_path: str
    fritzbox_bundle_path: str
    csr_mode: NotRequired[bool]
    common_name: NotRequired[str]
    name: NotRequired[str]
    profile: NotRequired[str]
    inventory_changed: NotRequired[bool]
