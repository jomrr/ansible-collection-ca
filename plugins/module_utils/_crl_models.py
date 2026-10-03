# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""CRL input, per-generation publication plan and persistent status schemas."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import NotRequired, TypedDict

from ansible_collections.jomrr.ca.plugins.module_utils._file import FileAttributes
from ansible_collections.jomrr.ca.plugins.module_utils._formats import normalize_formats
from ansible_collections.jomrr.ca.plugins.module_utils._input import InputValues


class Revocation(TypedDict):
    """Resolved, serial-bound revocation record."""

    record_type: str
    schema_version: int
    issuer: str
    serial_number: str
    serial_number_hex: str
    reason: str
    revocation_date: str
    invalidity_date: str
    source: str
    certificate_name: NotRequired[str]
    selector_name: NotRequired[str]
    fingerprints: NotRequired[dict[str, str]]


def revocation(value: Mapping[str, object]) -> Revocation:
    """Validate stored or freshly resolved records before CRL construction."""
    item = InputValues(value)
    result: Revocation = {
        "record_type": item.text("record_type"),
        "schema_version": item.integer("schema_version"),
        "issuer": item.text("issuer"),
        "serial_number": item.text("serial_number"),
        "serial_number_hex": item.text("serial_number_hex"),
        "reason": item.text("reason"),
        "revocation_date": item.text("revocation_date"),
        "invalidity_date": item.text("invalidity_date"),
        "source": item.text("source"),
    }
    if "certificate_name" in value:
        result["certificate_name"] = item.text("certificate_name")
    if "selector_name" in value:
        result["selector_name"] = item.text("selector_name")
    if "fingerprints" in value:
        result["fingerprints"] = item.text_mapping("fingerprints")
    return result


@dataclass
class CrlCredentials:
    """Credentials are input only; never persisted or displayed."""

    current: str = field(repr=False)
    archived: dict[str, str] = field(repr=False)


@dataclass
class CrlContext:
    """Storage and ownership of the issuing authority."""

    base_dir: str
    name: str
    ca_name: str
    base_url: str
    attributes: FileAttributes


@dataclass
class CrlPolicy:
    """Signing and renewal policy shared by active generations."""

    digest: str
    next_update_days: int
    renew_before_days: float
    force: bool


@dataclass
class CrlRequest:
    """Shared, validated input for all signing generations."""

    context: CrlContext
    policy: CrlPolicy
    credentials: CrlCredentials
    formats: list[str]
    revoked_certificates: list[Revocation]
    legacy_generation: str

    @classmethod
    def from_input(
        cls, params: Mapping[str, object], revoked: list[Revocation]
    ) -> CrlRequest:
        """Parse module input after resolving persistent revocations."""
        values = InputValues(params)
        return cls(
            context=CrlContext(
                base_dir=values.text("base_dir"),
                name=values.text("name"),
                ca_name=values.text("ca_name"),
                base_url=values.text("base_url"),
                attributes=FileAttributes(
                    values.text("owner") or None,
                    values.text("group") or None,
                    values.text("mode", "0644"),
                ),
            ),
            credentials=CrlCredentials(
                values.text("key_passphrase"),
                values.text_mapping("archived_key_passphrases"),
            ),
            formats=normalize_formats(
                params.get("formats"),
                defaults=("pem", "der"),
                supported={"pem", "der"},
                context="CRL",
            ),
            revoked_certificates=revoked,
            policy=CrlPolicy(
                digest=values.text("digest", "sha384"),
                next_update_days=values.integer("next_update_days", 30),
                renew_before_days=values.number("renew_before_days", 7),
                force=values.boolean("force"),
            ),
            legacy_generation=values.text("legacy_generation"),
        )


@dataclass
class CrlPlan:
    """Derived state for one issuer, separate from the module input."""

    request: CrlRequest
    identity: str
    suffix: str
    paths: dict[str, str]
    stop_at: datetime | None = None


class GenerationStatus(TypedDict):
    """Persisted retirement deadline and observed retirement state."""

    retire_at: str
    retired: bool


class GenerationResult(GenerationStatus):
    """Published CRL state for a generation."""

    paths: dict[str, str]
    crl_number: NotRequired[int]
