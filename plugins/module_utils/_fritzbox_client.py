# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal FRITZ!OS certificate client; not a public API."""

from __future__ import annotations

import hashlib
import secrets
import socket
import ssl
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Callable
from http.client import HTTPResponse
from typing import cast

from ansible.module_utils.urls import open_url

try:
    from cryptography import x509
except ImportError:
    pass

ZERO_SID = "0000000000000000"
SUCCESS_MARKERS = (
    "SSL-Zertifikat wurde erfolgreich importiert",
    "SSL certificate was successful",
    "certificado SSL se ha importado",
    "certificat SSL a été importé",
    "certificato SSL è stato importato",
    "certyfikatu SSL",
)


def _challenge_response(challenge: str, password: str) -> str:
    """Return a FRITZ!OS login response for legacy and PBKDF2 challenges."""
    if challenge.startswith("2$"):
        parts = challenge.split("$")
        if len(parts) != 5 or parts[0] != "2":
            raise RuntimeError("FRITZ!Box returned an unsupported PBKDF2 challenge")
        first_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-16le"),
            bytes.fromhex(parts[2]),
            int(parts[1]),
        )
        second_hash = hashlib.pbkdf2_hmac(
            "sha256",
            first_hash,
            bytes.fromhex(parts[4]),
            int(parts[3]),
        )
        return f"{challenge}${second_hash.hex()}"

    digest_input = f"{challenge}-{password}".encode("utf-16le")
    response_hash = hashlib.md5(digest_input).hexdigest()
    return f"{challenge}-{response_hash}"


def _deploy_url(value: str) -> str:
    """Return a normalized FRITZ!Box deployment URL."""
    url = str(value or "").strip().rstrip("/")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("url must be an absolute http or https URL")
    if parsed.username or parsed.password:
        raise ValueError("url must not contain credentials")
    host = parsed.hostname
    if not host:
        raise ValueError("url must contain a host name")
    hostname = host.lower()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = f"{hostname}:{parsed.port}" if parsed.port is not None else hostname
    return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))


def _https_endpoint(url: str) -> tuple[str, int]:
    """Return the HTTPS endpoint for the FRITZ!Box certificate comparison."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise ValueError("FritzBox deployment idempotence requires an https url")
    return parsed.hostname or "", parsed.port or 443


def _url(url: str, path: str, query: dict[str, str] | None = None) -> str:
    """Build an absolute FRITZ!OS URL below the deployment URL."""
    parsed = urllib.parse.urlsplit(url)
    encoded_query = urllib.parse.urlencode(query or {})
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, path, encoded_query, "")
    )


def _decode_response(response: HTTPResponse, data: bytes) -> str:
    """Decode an HTTP response body for XML and message checks."""
    encoding = response.headers.get_content_charset() or "utf-8"
    return data.decode(encoding, errors="replace")


def _ssl_context(validate_certs: bool) -> ssl.SSLContext:
    """Return an SSL context matching the certificate validation setting."""
    if validate_certs:
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class FritzBoxClient:
    """Small FRITZ!OS HTTP client for certificate import."""

    def __init__(
        self,
        *,
        url: str,
        username: str,
        password: str,
        timeout: int,
        validate_certs: bool,
    ) -> None:
        """Initialize the client connection settings."""
        self.url = _deploy_url(url)
        self.username = username
        self.password = password
        self.timeout = timeout
        self.context = _ssl_context(validate_certs)
        self.validate_certs = validate_certs
        self.sid = ""

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> str:
        """Execute one FRITZ!OS HTTP request and return decoded text."""
        url = _url(self.url, path, query)
        try:
            with cast(Callable[..., HTTPResponse], open_url)(
                url,
                data=data,
                headers=headers or {},
                method=method,
                timeout=self.timeout,
                validate_certs=self.validate_certs,
                follow_redirects="urllib2",
                use_netrc=False,
            ) as response:
                body = response.read()
                return _decode_response(response, body)
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"FRITZ!Box request failed with HTTP {exc.code}: {error_body[:400]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"FRITZ!Box request failed: {exc.reason}") from exc

    @staticmethod
    def _xml_text(xml_text: str, element: str) -> str:
        """Read one element text value from a FRITZ!OS XML response."""
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            raise RuntimeError("FRITZ!Box returned invalid XML") from exc
        value = root.findtext(f".//{element}") or ""
        return value.strip()

    def login(self) -> str:
        """Log in and return a valid FRITZ!OS SID."""
        login_xml = self._request("GET", "/login_sid.lua")
        challenge = self._xml_text(login_xml, "Challenge")
        if not challenge:
            raise RuntimeError("FRITZ!Box did not return a login challenge")

        auth_xml = self._request(
            "GET",
            "/login_sid.lua",
            query={
                "username": self.username,
                "response": _challenge_response(challenge, self.password),
            },
        )
        sid = self._xml_text(auth_xml, "SID")
        if not sid or sid == ZERO_SID:
            raise RuntimeError("FRITZ!Box login failed")
        self.sid = sid
        return sid

    def logout(self) -> None:
        """Log out and ignore logout transport errors."""
        if not self.sid or self.sid == ZERO_SID:
            return
        try:
            self._request(
                "GET",
                "/login_sid.lua",
                query={"logout": "1", "sid": self.sid},
            )
        except RuntimeError:
            pass

    def import_certificate(self, bundle: bytes) -> None:
        """Upload a certificate bundle and require a successful response."""
        sid = self.sid or self.login()
        boundary = f"ansible-ca-{secrets.token_hex(16)}"
        body = _multipart_body(boundary, sid, bundle)
        response = self._request(
            "POST",
            "/cgi-bin/firmwarecfg",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        if not _import_succeeded(response):
            raise RuntimeError("FRITZ!Box did not confirm certificate import")

    def current_certificate(self) -> x509.Certificate:
        """Return the certificate currently served by the FRITZ!Box HTTPS port."""
        host, port = _https_endpoint(self.url)
        if not host:
            raise ValueError("url does not contain a host name")
        try:
            raw_socket = socket.create_connection((host, port), self.timeout)
            with (
                raw_socket,
                self.context.wrap_socket(raw_socket, server_hostname=host) as sock,
            ):
                der_certificate = sock.getpeercert(binary_form=True)
        except OSError as exc:
            raise RuntimeError(
                f"Failed to read current FRITZ!Box certificate: {exc}"
            ) from exc
        if not der_certificate:
            raise RuntimeError("FRITZ!Box did not present an HTTPS certificate")
        return x509.load_der_x509_certificate(der_certificate)


def _multipart_body(boundary: str, sid: str, bundle: bytes) -> bytes:
    """Build the multipart/form-data upload body for firmwarecfg."""
    boundary_bytes = boundary.encode("ascii")
    return b"".join(
        [
            b"--" + boundary_bytes + b"\r\n",
            b'Content-Disposition: form-data; name="sid"\r\n\r\n',
            sid.encode("ascii"),
            b"\r\n--" + boundary_bytes + b"\r\n",
            (
                b'Content-Disposition: form-data; name="BoxCertImportFile"; '
                b'filename="BoxCert.pem"\r\n'
            ),
            b"Content-Type: application/octet-stream\r\n\r\n",
            bundle,
            b"\r\n--" + boundary_bytes + b"--\r\n",
        ]
    )


def _import_succeeded(response: str) -> bool:
    """Return whether the FRITZ!OS import response contains a success marker."""
    return any(marker in response for marker in SUCCESS_MARKERS)
