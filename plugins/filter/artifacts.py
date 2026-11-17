# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Describe configured certificate files without inspecting CA state."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import PurePosixPath
from typing import TypedDict

from ansible.errors import AnsibleFilterError
from ansible.plugins import AnsiblePlugin
from ansible_collections.jomrr.ca.plugins.module_utils._formats import (
    CERTIFICATE_DEFAULT_FORMATS,
    CERTIFICATE_SUPPORTED_FORMATS,
    DEFAULT_PUBLIC_FORMATS,
    normalize_formats,
)
from ansible_collections.jomrr.ca.plugins.module_utils._input import InputValues
from ansible_collections.jomrr.ca.plugins.module_utils._paths import (
    authority_paths,
    certificate_paths,
)
from ansible_collections.jomrr.ca.plugins.module_utils._validation import safe_name

DOCUMENTATION = r"""
name: artifacts
short_description: List configured public and opted-in private certificate files
version_added: 1.3.0
description:
- Return one entry per configured file, sorted by C(src), relative to C(base_dir).
- Authorities contribute PEM and selected DER, CER and TXT exports. Their default
  formats are C(pem), C(der) and C(txt). Authority keys are never listed.
- Certificates contribute PEM and chain files plus selected formats, using their
  profile defaults when C(formats) is omitted. Duplicate formats produce one entry.
- Private files are listed only with C(publish_private=true) in the certificate
  definition. These are the local key and requested C(bundle), C(fritzbox), C(pfx)
  and C(p12) exports; each has C(secret=true). External CSRs have no local key.
- Runs on the controller without reading files or requiring cryptography.
- This is a manifest of configured current files after successful issuance, not
  a directory scan. It excludes archived generations, CSRs, CRLs and CA chains.
- A non-empty C(output_dir) is rejected because this signature has no C(base_dir)
  with which to derive relative paths. Use the modules' default file layout.
author:
- Jonas Mauer (@jomrr)
positional: [authorities]
options:
  _input:
    description:
    - Certificate definitions accepted by M(jomrr.ca.certificate_batch).
    - Each entry needs C(name) and C(type). C(publish_private) must be a boolean
      and defaults to V(false). It controls this manifest only, not issuance.
    type: list
    elements: dict
    required: true
  authorities:
    description: Authority definitions with C(name) and optional C(formats).
    type: list
    elements: dict
    required: true
"""

EXAMPLES = r"""
ca_artifacts: "{{ ca_certificates | jomrr.ca.artifacts(ca_authorities) }}"

# Select public files for a downstream transfer task.
ca_public_artifacts: >-
  {{ ca_certificates | jomrr.ca.artifacts(ca_authorities) |
     rejectattr('secret') | list }}

# Opt in to handling this device's key and requested private export.
ca_certificates:
  - name: scanner
    type: tls_server
    common_name: scanner.example.test
    formats: [cer, pfx]
    pfx_passphrase: "{{ vault_scanner_pfx_passphrase }}"
    publish_private: true
"""

RETURN = r"""
_value:
  description:
  - File entries with C(src), C(owner), C(format) and C(secret).
  - C(owner) is the certificate or authority name, not a filesystem user.
  - C(format) is C(pem), C(chain), C(fullchain), C(der), C(cer), C(txt), C(key),
    C(bundle), C(fritzbox), C(pfx) or C(p12). C(src) retains alias filenames.
  type: list
  elements: dict
  sample:
  - src: certs/web01/web01-fullchain.pem
    owner: web01
    format: fullchain
    secret: false
"""

_PATH_KEYS = {
    "pem": "certificate_pem",
    "der": "certificate_der",
    "cer": "certificate_cer",
    "txt": "certificate_text",
    "chain": "chain",
    "fullchain": "fullchain",
    "key": "private_key",
    "bundle": "bundle",
    "fritzbox": "fritzbox_bundle",
    "pfx": "pkcs12_pfx",
    "p12": "pkcs12_p12",
}
_PRIVATE_FORMATS = frozenset({"key", "bundle", "fritzbox", "pfx", "p12"})
_AUTHORITY_FORMATS = frozenset({*DEFAULT_PUBLIC_FORMATS, "cer"})


class Artifact(TypedDict):
    """A relative file path with its object identity and confidentiality."""

    src: str
    owner: str
    format: str
    secret: bool


def _definitions(value: object, context: str) -> dict[str, InputValues]:
    """Read only the fields needed for paths, leaving unrelated secrets untouched."""
    if not isinstance(value, list):
        raise TypeError(f"{context} must be a list")
    result = {}
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError(f"Each {context} entry must be a dictionary")
        fields = InputValues(item)
        name = safe_name(fields.text("name"), context)
        if name in (".", ".."):
            raise ValueError(f"{context} name must not be a path component")
        if name in result:
            raise ValueError(f"Duplicate {context} name {name}")
        if fields.text("output_dir"):
            raise ValueError(
                f"{context} {name}: output_dir is not supported by artifacts"
            )
        result[name] = fields
    return result


def _certificate_formats(fields: InputValues) -> set[str]:
    """Use issuance defaults and gate all private aliases behind explicit opt-in."""
    profile = fields.text("type")
    if profile not in CERTIFICATE_DEFAULT_FORMATS:
        raise ValueError(f"Unsupported certificate type {profile}")
    requested = (
        CERTIFICATE_DEFAULT_FORMATS[profile]
        if fields.values.get("formats") is None
        else fields.strings("formats")
    )
    formats = set(normalize_formats(requested, supported=CERTIFICATE_SUPPORTED_FORMATS))
    external = bool(fields.text("csr_path") or fields.text("csr_content"))
    if external and formats.intersection(_PRIVATE_FORMATS):
        raise ValueError("External CSRs cannot request private export formats")
    if fields.boolean("publish_private"):
        if not external:
            formats.add("key")
    else:
        formats.difference_update(_PRIVATE_FORMATS)
    return formats | {"pem", "chain"}


def _entries(name: str, paths: dict[str, str], formats: set[str]) -> list[Artifact]:
    """Map formats to paths owned by the same layout helper as the writers."""
    return [
        Artifact(
            src=PurePosixPath(paths[_PATH_KEYS[format_name]]).as_posix(),
            owner=name,
            format=format_name,
            secret=format_name in _PRIVATE_FORMATS,
        )
        for format_name in formats
    ]


def artifacts(certificates: object, authorities: object) -> list[Artifact]:
    """Return the current configured files for the collection's default layout."""
    try:
        result = []
        for name, fields in _definitions(authorities, "authority").items():
            formats = set(
                normalize_formats(
                    list(DEFAULT_PUBLIC_FORMATS)
                    if fields.values.get("formats") is None
                    else fields.strings("formats"),
                    supported=_AUTHORITY_FORMATS,
                    context="authority",
                )
            )
            result.extend(_entries(name, authority_paths(".", name), formats | {"pem"}))
        for name, fields in _definitions(certificates, "certificate").items():
            result.extend(
                _entries(
                    name, certificate_paths(".", name), _certificate_formats(fields)
                )
            )
        return sorted(result, key=lambda item: item["src"])
    except (TypeError, ValueError) as exc:
        raise AnsibleFilterError(str(exc)) from exc


class FilterModule(AnsiblePlugin):
    """Ansible filter plugin entry point."""

    def filters(self) -> dict[str, Callable[..., list[Artifact]]]:
        """Expose the artifact manifest through Ansible's loader."""
        return {"artifacts": artifacts}
