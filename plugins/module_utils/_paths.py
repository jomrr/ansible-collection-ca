# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Internal filesystem layout shared by issuance, inventory and publication."""

from __future__ import annotations

from collections.abc import Collection, Iterable
from pathlib import Path


def _path(base_dir: str, *parts: str) -> str:
    """Join layout components without resolving or rewriting caller paths."""
    return "/".join((str(base_dir).rstrip("/"), *parts))


def authority_directory(base_dir: str) -> Path:
    """Return the directory containing current managed CA certificates."""
    return Path(_path(base_dir, "ca"))


def chain_paths(
    base_dir: str, name: str, formats: Iterable[str] = ("pem", "der", "txt")
) -> dict[str, str]:
    """Return the requested CA chain exports, preserving format order."""
    return {
        format_name: _path(base_dir, "chains", f"{name}-ca-chain.{format_name}")
        for format_name in formats
    }


def crl_paths(
    base_dir: str, stem: str, formats: Collection[str] = ("pem", "der")
) -> dict[str, str]:
    """Return CRL exports for a legacy or generation-specific CA filename stem."""
    return {
        format_name: _path(base_dir, "crl", f"{stem}.{suffix}")
        for format_name, suffix in (("pem", "crl.pem"), ("der", "crl"))
        if format_name in formats
    }


def authority_paths(
    base_dir: str, name: str, *, include_chain: bool = False
) -> dict[str, str]:
    """Return current managed CA material and its legacy public exports."""
    stem = f"{name}-ca"
    paths = {
        "private_key": _path(base_dir, "private", f"{stem}.key"),
        "csr": _path(base_dir, "csr", f"{stem}.csr"),
        "certificate_pem": _path(base_dir, "ca", f"{stem}.pem"),
        "certificate_der": _path(base_dir, "ca", f"{stem}.der"),
        "certificate_text": _path(base_dir, "ca", f"{stem}.txt"),
        **{f"crl_{kind}": path for kind, path in crl_paths(base_dir, stem).items()},
    }
    if include_chain:
        paths["chain"] = chain_paths(base_dir, name, ("pem",))["pem"]
    return paths


def certificate_paths(
    base_dir: str, name: str, output_dir: str | None = None
) -> dict[str, str]:
    """Return all certificate artifact paths, honoring a custom output directory."""
    directory = (output_dir or _path(base_dir, "certs", name)).rstrip("/")
    return {
        "output_dir": directory,
        "private_key": f"{directory}/{name}.key",
        "csr": _path(base_dir, "csr", f"{name}.csr"),
        "certificate_pem": f"{directory}/{name}.pem",
        "certificate_der": f"{directory}/{name}.der",
        "certificate_text": f"{directory}/{name}.txt",
        "chain": f"{directory}/{name}-chain.pem",
        "fullchain": f"{directory}/{name}-fullchain.pem",
        "fritzbox_bundle": f"{directory}/{name}-fritzbox.pem",
        "pkcs12_pfx": f"{directory}/{name}.pfx",
        "pkcs12_p12": f"{directory}/{name}.p12",
    }


def archive_directory(
    base_dir: str, name: str, *, authority: bool, serial: str | None = None
) -> str:
    """Return an object's archive root or a specific certificate generation."""
    kind = "authorities" if authority else "certificates"
    root = _path(base_dir, "archive", kind, name)
    return f"{root}/{serial}" if serial is not None else root


def generation_directory(base_dir: str, name: str) -> Path:
    """Return the public generation directory for a validated authority name."""
    return Path(_path(base_dir, "generations", name))


def inventory_path(base_dir: str, *parts: str) -> str:
    """Return a composed inventory or inventory state path."""
    return _path(base_dir, "inventory", *parts)


def lock_path(base_dir: str, stem: str) -> str:
    """Return an object's lock path for a sanitized lock filename stem."""
    return _path(base_dir, ".locks", f"{stem}.lock")
