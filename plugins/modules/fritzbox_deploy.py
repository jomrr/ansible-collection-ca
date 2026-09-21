# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Deploy a FritzBox PEM certificate bundle to FRITZ!OS."""

from __future__ import annotations

DOCUMENTATION = r"""
module: fritzbox_deploy
short_description: Deploy a FritzBox PEM certificate bundle to FRITZ!OS
version_added: 0.1.0
description:
- Deploy a FritzBox PEM certificate bundle to FRITZ!OS.
author:
- Jonas Mauer (@jomrr)
extends_documentation_fragment:
- jomrr.ca.context
attributes:
  check_mode:
    support: none
    description: Skipped in check mode without changing the managed host.
  diff_mode:
    support: none
    description: No diff output is returned.
requirements:
- Python 3.12 on the managed Linux host
- cryptography >= 43 on the managed host
notes:
- The base directory and persistent inventory must be preserved between runs.
- Private utilities are internal implementation details and are not a public API.
- TLS verification defaults to false for self-signed FRITZ!Box device certificates. Enable
  validate_certs when the device certificate is trusted.
options:
  certificate:
    description: Optional source for C(output_dir) and nested C(fritzbox_deploy).
    version_added: 0.1.0
    type: dict
  deploy:
    description: Explicit deployment settings. Values override nested C(certificate.fritzbox_deploy).
    version_added: 0.1.0
    type: dict
  name:
    description: Certificate short name and file stem.
    version_added: 0.1.0
    type: str
    required: true
  output_dir:
    description: Directory containing the generated FritzBox bundle.
    version_added: 0.1.0
    type: path
  bundle_path:
    description: Explicit FritzBox bundle path.
    version_added: 0.1.0
    type: path
  url:
    description: FRITZ!Box URL. HTTPS is required for idempotence comparison.
    version_added: 0.1.0
    type: str
    default: https://fritz.box
  username:
    description: Login user.
    version_added: 0.1.0
    type: str
  password:
    description: Login password.
    version_added: 0.1.0
    type: str
  timeout:
    description: Network timeout in seconds.
    version_added: 0.1.0
    type: int
  validate_certs:
    description: Validate the current FRITZ!Box HTTPS certificate while connecting.
    version_added: 0.1.0
    type: bool
    default: false
"""

EXAMPLES = r"""
- name: Deploy FritzBox certificate
  jomrr.ca.fritzbox_deploy:
    base_dir: /etc/pki/example
    name: fritzbox
    username: "{{ fritzbox_username }}"
    password: "{{ fritzbox_password }}"

- name: Deploy configured FritzBox certificate
  jomrr.ca.fritzbox_deploy:
    base_dir: /etc/pki/example
    name: "{{ certificate.name }}"
    certificate: "{{ certificate }}"
"""

RETURN = r"""
path:
  description: Bundle path used for deployment.
  type: str
  returned: success
"""

# Ansible requires DOCUMENTATION, EXAMPLES and RETURN before normal imports.
# pylint: disable=wrong-import-position
import re
from collections.abc import Callable
from typing import Any, cast

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.jomrr.ca.plugins.module_utils._dependency import (
    OPERATION_ERRORS,
    require_cryptography,
)
from ansible_collections.jomrr.ca.plugins.module_utils._file import (
    ca_lock_path,
    file_lock,
    read_file,
    sanitize_error,
)
from ansible_collections.jomrr.ca.plugins.module_utils._fritzbox_client import (
    FritzBoxClient,
    _deploy_url,
)

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    pass

# pylint: enable=wrong-import-position


PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN (?:RSA |ENCRYPTED |)PRIVATE KEY-----.*?"
    rb"-----END (?:RSA |ENCRYPTED |)PRIVATE KEY-----",
    re.DOTALL,
)
CERTIFICATE_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def _bundle_path(base_dir: str, name: str, output_dir: str | None) -> str:
    """Derive the FritzBox bundle path."""
    directory = (output_dir or f"{base_dir.rstrip('/')}/certs/{name}").rstrip("/")
    return f"{directory}/{name}-fritzbox.pem"


def _deploy_lock_path(base_dir: str, url: str) -> str:
    """Return the local lock path for one FRITZ!Box deployment target."""
    return ca_lock_path(base_dir, "fritzbox-deploy", _deploy_url(url))


def _params(params: dict[str, Any]) -> dict[str, Any]:
    """Merge certificate and deploy dictionaries into explicit module params."""
    certificate = dict(params.get("certificate") or {})
    deploy = dict(certificate.get("fritzbox_deploy") or {})
    deploy.update(dict(params.get("deploy") or {}))

    result = dict(params)
    if result.get("output_dir") is None and certificate.get("output_dir") is not None:
        result["output_dir"] = certificate["output_dir"]
    for key in (
        "url",
        "username",
        "password",
        "bundle_path",
        "timeout",
        "validate_certs",
        "force",
    ):
        if deploy.get(key) is not None:
            result[key] = deploy[key]
    if not result.get("url"):
        result["url"] = "https://fritz.box"
    result["url"] = _deploy_url(result["url"])
    if result.get("timeout") is None:
        result["timeout"] = 30
    if result.get("validate_certs") is None:
        result["validate_certs"] = False
    if not result.get("bundle_path"):
        result["bundle_path"] = _bundle_path(
            result["base_dir"], result["name"], result.get("output_dir")
        )
    return result


def _load_bundle(path: str) -> bytes:
    """Read and normalize the FritzBox PEM bundle."""
    return read_file(path).strip() + b"\n"


def _leaf_certificate(bundle: bytes) -> x509.Certificate:
    """Return the first certificate from the FritzBox PEM bundle."""
    match = CERTIFICATE_RE.search(bundle)
    if match is None:
        raise ValueError("FritzBox bundle does not contain a certificate")
    return x509.load_pem_x509_certificate(match.group(0))


def _private_key_pem(bundle: bytes) -> bytes:
    """Extract the first private key PEM block from a bundle."""
    match = PRIVATE_KEY_RE.search(bundle)
    if match is None:
        raise ValueError("FritzBox bundle does not contain a private key")
    return match.group(0)


def _private_key_is_encrypted(key_pem: bytes) -> bool:
    """Return whether a PEM private key block is encrypted."""
    first_line = key_pem.splitlines()[0]
    return b"ENCRYPTED" in first_line or b"Proc-Type: 4,ENCRYPTED" in key_pem


def _validate_bundle(bundle: bytes) -> None:
    """Validate that the bundle contains certificates and an RSA private key."""
    certificates = CERTIFICATE_RE.findall(bundle)
    if not certificates:
        raise ValueError("FritzBox bundle does not contain a certificate")
    for certificate in certificates:
        x509.load_pem_x509_certificate(certificate)

    key_pem = _private_key_pem(bundle)
    if _private_key_is_encrypted(key_pem):
        raise ValueError("FRITZ!OS certificate import requires an unencrypted RSA key")
    try:
        private_key = serialization.load_pem_private_key(
            key_pem,
            password=None,
        )
    except TypeError as exc:
        raise ValueError("FritzBox bundle private key is not readable") from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("FRITZ!OS certificate import requires an RSA private key")


def _same_certificate(first: x509.Certificate, second: x509.Certificate) -> bool:
    """Return whether two certificates have the same SHA-256 fingerprint."""
    return first.fingerprint(hashes.SHA256()) == second.fingerprint(hashes.SHA256())


def run_module() -> None:
    """Run the Ansible module for FritzBox certificate deployment."""
    module = cast(Callable[..., AnsibleModule], AnsibleModule)(
        argument_spec={
            "base_dir": {"type": "path", "required": True},
            "certificate": {"type": "dict", "no_log": True},
            "deploy": {"type": "dict", "no_log": True},
            "name": {"type": "str", "required": True},
            "output_dir": {"type": "path"},
            "bundle_path": {"type": "path"},
            "url": {"type": "str", "default": "https://fritz.box"},
            "username": {"type": "str"},
            "password": {"type": "str", "no_log": True},
            "timeout": {"type": "int"},
            "validate_certs": {"type": "bool", "default": False},
            "force": {"type": "bool", "default": False},
        },
        supports_check_mode=False,
    )

    require_cryptography(module)

    client: FritzBoxClient | None = None
    try:
        params = _params(module.params)
        for key in ("username", "password"):
            if not params.get(key):
                raise ValueError(f"FritzBox deployment requires {key}")
        bundle = _load_bundle(params["bundle_path"])
        _validate_bundle(bundle)
        desired_certificate = _leaf_certificate(bundle)
        client = FritzBoxClient(
            url=params["url"],
            username=params["username"],
            password=params["password"],
            timeout=params["timeout"],
            validate_certs=params["validate_certs"],
        )
        with file_lock(_deploy_lock_path(params["base_dir"], params["url"])):
            if not params["force"] and _same_certificate(
                desired_certificate,
                client.current_certificate(),
            ):
                module.exit_json(changed=False, path=params["bundle_path"])
            client.login()
            client.import_certificate(bundle)
    except OPERATION_ERRORS as exc:
        module.fail_json(msg=sanitize_error(exc, module.params))
    finally:
        if client is not None:
            client.logout()

    module.exit_json(changed=True, path=params["bundle_path"])


def main() -> None:
    """Execute the module entry point."""
    run_module()


if __name__ == "__main__":
    main()
