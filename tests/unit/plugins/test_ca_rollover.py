# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""CA rollovers must retain usable issuer certificates and revocation services."""

from __future__ import annotations

import io
import json
import shutil
import tarfile
from datetime import timedelta
from pathlib import Path
from tempfile import mkdtemp
from typing import Any
from unittest import TestCase
from unittest.mock import patch

from ansible_collections.jomrr.ca.plugins.module_utils._authority_generations import (
    generation_id,
)
from ansible_collections.jomrr.ca.plugins.module_utils._crl_engine import ensure_crls
from ansible_collections.jomrr.ca.plugins.module_utils._time import (
    certificate_not_valid_after,
)
from ansible_collections.jomrr.ca.plugins.module_utils._x509_keys import (
    load_certificate,
)
from ansible_collections.jomrr.ca.plugins.modules.publish_archive import (
    _archive_content,
    _artifacts_from_authorities,
)
from ansible_collections.jomrr.ca.tests.integration.targets.authority.files import (
    rollover,
)
from ansible_collections.jomrr.ca.tests.unit.plugins.certificate_fixture import (
    CertificateFixture,
)
from cryptography import x509


class TestCaRollover(TestCase):
    """Exercise real issuance, CRL state, publication and OpenSSL verification."""

    def setUp(self) -> None:
        self.base = Path(mkdtemp())
        self.addCleanup(shutil.rmtree, self.base)
        self.ca = CertificateFixture(self.base)

    def crl(self, name: str = "issuer", **overrides: Any) -> dict[str, Any]:
        """Use the CRL engine with ordinary module defaults."""
        params = {
            "base_dir": str(self.base),
            "name": name,
            "key_passphrase": "test-passphrase",
            "formats": ["pem", "der"],
            "next_update_days": 30,
            "renew_before_days": 7,
            "revoked_certificates": [],
            "digest": "sha384",
            "force": False,
            "mode": "0644",
            "owner": None,
            "group": None,
        }
        params.update(overrides)
        return ensure_crls(params)

    def leaf(self, name: str, days: int = 90) -> x509.Certificate:
        """Issue a real leaf with issuer URLs derived by the normal dispatcher."""
        return self.ca.leaf(name, days=days, base_url="http://pki.example.test")

    def publish(self) -> dict[str, bytes]:
        """Read the actual authority-derived tar without extracting private data."""
        artifacts = _artifacts_from_authorities(
            [{"name": "root", "parent": "root"}, {"name": "issuer", "parent": "root"}],
            str(self.base),
        )
        # The shared fixture only exports its chain as PEM.
        artifacts = [item for item in artifacts if item["kind"] != "chain"]
        content, _paths = _archive_content(artifacts, "0644")
        result = {}
        with tarfile.open(fileobj=io.BytesIO(content)) as archive:
            for member in archive.getmembers():
                stream = archive.extractfile(member)
                assert stream is not None
                result[member.name] = stream.read()
        return result

    def test_old_and_new_generations_remain_revocable_and_published(self) -> None:
        """Two rekeys preserve legacy URLs and independently renew every CRL."""
        # Adopt pre-upgrade material with no generation registry.
        shutil.rmtree(self.base / "generations")
        self.crl("root")
        first_crls = self.crl()
        self.leaf("old")
        original = (self.base / "ca/issuer-ca.pem").read_bytes()
        # A certificate renewal without rekey must not invent another generation.
        self.ca.authority(
            "issuer", "root", days=400, renewal={"renew_before_days": 366}
        )
        self.assertEqual(len(self.crl()["generations"]), 1)
        for index in range(2):
            self.ca.authority("issuer", "root", force=True, renewal={"rekey": True})
            self.leaf(f"new{index}")
        result = self.crl(
            revoked_certificates=[{"name": "old", "reason": "key_compromise"}]
        )
        self.assertEqual(len(result["generations"]), 3)
        self.assertFalse(self.crl()["changed"])
        published = self.publish()
        legacy = x509.load_der_x509_certificate(published["aia/issuer-ca.der"])
        self.assertEqual(
            generation_id(legacy.subject, legacy.public_key()),
            generation_id(
                x509.load_pem_x509_certificate(original).subject,
                x509.load_pem_x509_certificate(original).public_key(),
            ),
        )
        locations = {
            rollover.verify(self.base, name, published)[0]
            for name in ("old", "new0", "new1")
        }
        self.assertEqual(len(locations), 3)
        legacy_id = next(iter(first_crls["generations"]))
        self.assertEqual(result["generations"][legacy_id]["crl_number"], 2)
        self.assertEqual(result["crl_number"], 2)
        # Missing exports are rebuilt without resetting the generation's counter.
        Path(result["paths"]["der"]).unlink()
        regenerated = self.crl()
        self.assertEqual(regenerated["crl_number"], 3)
        self.assertEqual(regenerated["generations"][legacy_id]["crl_number"], 3)

    def test_missing_archived_key_fails_before_any_crl_write(self) -> None:
        """A partially successful new CRL must never hide a broken old generation."""
        old = self.crl()
        self.ca.authority("issuer", "root", force=True)
        old_path = Path(old["paths"]["der"])
        before = old_path.read_bytes()
        for key in self.base.glob("archive/authorities/issuer/*/*.key"):
            key.unlink()
        with self.assertRaisesRegex(ValueError, "No usable signing key"):
            self.crl(revoked_certificates=[{"serial_number": 42}])
        self.assertEqual(old_path.read_bytes(), before)
        self.assertEqual(len(list((self.base / "crl").glob("*.crl"))), 1)

    def test_old_passphrase_can_be_supplied_per_generation(self) -> None:
        """A passphrase change does not render archived signing keys inaccessible."""
        before = self.crl()
        old_id = next(iter(before["generations"]))
        self.ca.authority(
            "issuer", "root", force=True, key_passphrase="new-test-passphrase"
        )
        with self.assertRaisesRegex(ValueError, "archived_key_passphrases"):
            self.crl(key_passphrase="new-test-passphrase")
        result = self.crl(
            key_passphrase="new-test-passphrase",
            archived_key_passphrases={old_id: "test-passphrase"},
        )
        self.assertEqual(len(result["generations"]), 2)
        self.assertFalse(
            self.crl(
                key_passphrase="new-test-passphrase",
                archived_key_passphrases={old_id: "test-passphrase"},
            )["changed"]
        )

    def legacy_rollover(self, *, new_leaf: bool) -> str:
        """Emulate the previous engine: archive keys but reuse its fixed URLs."""
        old_crls = self.crl()
        self.leaf("old")
        # Disable only the new URL/retention additions while constructing old state.
        with (
            patch(
                "ansible_collections.jomrr.ca.plugins.module_utils._x509.issuer_urls"
            ),
            patch(
                "ansible_collections.jomrr.ca.plugins.module_utils._x509."
                "retain_generation",
                return_value=False,
            ),
        ):
            self.ca.authority("issuer", "root", force=True)
            if new_leaf:
                self.leaf("new")
        shutil.rmtree(self.base / "generations")
        # Earlier inventory summaries did not record AKI; use real stored PEMs.
        for path in self.base.glob("inventory/state/issued_certificates/**/*.json"):
            record = json.loads(path.read_text())
            record["certificate"]["extensions"].pop("authority_key_identifier", None)
            path.write_text(json.dumps(record))
        return str(next(iter(old_crls["generations"])))

    def test_pre_upgrade_rollover_is_recovered_from_archived_keys(self) -> None:
        """An already performed rollover can adopt its old key and fixed URLs."""
        old_id = self.legacy_rollover(new_leaf=False)
        result = self.crl(
            revoked_certificates=[{"name": "old", "reason": "superseded"}]
        )
        self.assertEqual(result["legacy_generation"], old_id)
        self.assertEqual(result["migration_conflicts"], [])
        self.assertEqual(len(result["generations"]), 2)
        self.crl("root")
        self.leaf("new")
        published = self.publish()
        self.assertEqual(
            rollover.verify(self.base, "old", published)[0], "aia/issuer-ca.der"
        )
        self.assertNotEqual(
            rollover.verify(self.base, "new", published)[0], "aia/issuer-ca.der"
        )

    def test_conflicting_legacy_urls_need_explicit_owner_and_reissuance(self) -> None:
        """Report certificates with conflicting legacy URLs during migration."""
        old_id = self.legacy_rollover(new_leaf=True)
        with self.assertRaisesRegex(ValueError, "Select legacy_generation"):
            self.crl()
        result = self.crl(legacy_generation=old_id)
        self.assertEqual(
            [record["name"] for record in result["migration_conflicts"]], ["new"]
        )
        conflict = result["migration_conflicts"][0]
        self.leaf("new")
        result = self.crl(
            revoked_certificates=[
                {"serial_number": conflict["serial_number"], "reason": "superseded"}
            ]
        )
        self.assertEqual(result["migration_conflicts"], [])
        self.assertFalse(self.crl()["changed"])

    def test_old_key_is_not_needed_after_the_last_leaf_expires(self) -> None:
        """Stop using the old key when its last certificate expires."""
        leaf = self.leaf("short", days=1)
        before = self.crl()
        old_id = before["legacy_generation"]
        self.ca.authority("issuer", "root", force=True)
        result = self.crl()
        old_crl = Path(result["generations"][old_id]["paths"]["der"])
        content = old_crl.read_bytes()
        crl = x509.load_der_x509_crl(content)
        assert crl.next_update_utc is not None
        self.assertLessEqual(crl.next_update_utc, certificate_not_valid_after(leaf))
        self.assertFalse(self.crl()["changed"])
        for key in self.base.glob("archive/authorities/issuer/*/*.key"):
            key.unlink()
        after_expiry = certificate_not_valid_after(leaf) + timedelta(seconds=1)
        with (
            patch(
                "ansible_collections.jomrr.ca.plugins.module_utils._crl_engine.now_utc",
                return_value=after_expiry,
            ),
            patch(
                "ansible_collections.jomrr.ca.plugins.module_utils._crl.now_utc",
                return_value=after_expiry,
            ),
        ):
            retired = self.crl()
            self.assertTrue(retired["generations"][old_id]["retired"])
            self.assertFalse(
                retired["generations"][
                    next(key for key in retired["generations"] if key != old_id)
                ]["retired"]
            )
            self.assertEqual(old_crl.read_bytes(), content)
            self.assertFalse(self.crl()["changed"])

    def test_retirement_is_bounded_by_ca_expiry_when_history_is_missing(self) -> None:
        """Even incomplete old inventory must not require the key indefinitely."""
        old_cert = load_certificate(str(self.base / "ca/issuer-ca.pem"))
        old = self.crl()
        old_id = old["legacy_generation"]
        self.ca.authority("issuer", "root", force=True, days=730)
        self.crl()
        for key in self.base.glob("archive/authorities/issuer/*/*.key"):
            key.unlink()
        after_expiry = certificate_not_valid_after(old_cert) + timedelta(seconds=1)
        with (
            patch(
                "ansible_collections.jomrr.ca.plugins.module_utils._crl_engine.now_utc",
                return_value=after_expiry,
            ),
            patch(
                "ansible_collections.jomrr.ca.plugins.module_utils._crl.now_utc",
                return_value=after_expiry,
            ),
        ):
            retired = self.crl()
            self.assertTrue(retired["generations"][old_id]["retired"])
