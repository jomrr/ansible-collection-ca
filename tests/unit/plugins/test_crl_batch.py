# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""CRL batches preserve authority-specific policy and generation state."""

from __future__ import annotations

import copy
import fcntl
import json
import os
import shutil
from collections import Counter
from pathlib import Path
from tempfile import mkdtemp
from typing import Any
from unittest import TestCase
from unittest.mock import patch

from ansible_collections.jomrr.ca.plugins.module_utils._file import ca_lock_path
from ansible_collections.jomrr.ca.plugins.modules import crl_batch
from ansible_collections.jomrr.ca.tests.unit.plugins.batch_check_fixture import (
    forbid_mutation,
    snapshot,
)
from ansible_collections.jomrr.ca.tests.unit.plugins.certificate_fixture import (
    CertificateFixture,
)
from ansible_collections.jomrr.ca.tests.unit.plugins.module_fixture import (
    module_diagnostics,
    module_transport,
)
from cryptography import x509


class CrlBatchTests(TestCase):
    """Exercise real Ansible decoding, signing, files, locks and redaction."""

    def setUp(self) -> None:
        self.base = Path(mkdtemp())
        self.addCleanup(shutil.rmtree, self.base)
        self.ca = CertificateFixture(self.base)
        self.leaf = self.ca.leaf("leaf")
        self.authorities: list[dict[str, Any]] = [
            {
                "name": "issuer",
                "parent": "root",
                "key_passphrase": "test-passphrase",
                "crl_days": 2,
                "crl_renew_before_days": 0.5,
                "crl_digest": "sha256",
                "digest": "sha512",
            },
            {
                "name": "root",
                "parent": "root",
                "key_passphrase": "test-passphrase",
                "crl_days": 30,
            },
        ]
        self.params: dict[str, Any] = {
            "base_dir": str(self.base),
            "ca_name": "batch",
            "base_url": "http://pki.example.test",
            "authorities": self.authorities,
            "renew_before_days": 5,
            "owner": str(os.getuid()),
            "group": str(os.getgid()),
        }

    def invoke(self, **overrides: Any) -> dict[str, Any]:
        """Inspect real module output and syslog, including operational failures."""
        inputs = {**copy.deepcopy(self.params), **overrides}
        with module_transport(inputs) as (output, log), self.assertRaises(SystemExit):
            crl_batch.main()
        emitted = module_diagnostics(output, log)
        for secret in ("test-passphrase", "rotated-crl-secret", "wrong-crl-secret"):
            self.assertNotIn(secret, emitted)
        result: dict[str, Any] = json.loads(output.getvalue())
        return result

    def load_crl(self, name: str) -> x509.CertificateRevocationList:
        """Read the actual original-generation DER export."""
        return x509.load_der_x509_crl((self.base / f"crl/{name}-ca.crl").read_bytes())

    def test_policy_mapping_and_independent_locks(self) -> None:
        """Use different windows/digests while holding only one authority at a time."""
        acquired: Counter[str] = Counter()
        live: set[str] = set()
        authority_locks = {
            ca_lock_path(str(self.base), "authority", name)
            for name in ("issuer", "root")
        }
        flock = fcntl.flock

        def record(fd: int, operation: int) -> None:
            path = os.readlink(f"/proc/self/fd/{fd}")
            if operation == fcntl.LOCK_EX:
                acquired[path] += 1
                live.add(path)
                self.assertLessEqual(len(live & authority_locks), 1)
                operation |= fcntl.LOCK_NB
            else:
                live.discard(path)
            flock(fd, operation)

        with patch.object(fcntl, "flock", side_effect=record):
            result = self.invoke()
        self.assertNotIn("failed", result)
        self.assertTrue(result["changed"])
        self.assertEqual(result["count"], 2)
        self.assertEqual(
            [item["name"] for item in result["results"]], ["issuer", "root"]
        )
        for name, days, digest in (("issuer", 2, "sha256"), ("root", 30, "sha384")):
            for kind in ("authority", "crl"):
                self.assertEqual(acquired[ca_lock_path(str(self.base), kind, name)], 1)
            crl = self.load_crl(name)
            next_update = crl.next_update_utc
            algorithm = crl.signature_hash_algorithm
            assert next_update is not None
            assert algorithm is not None
            self.assertEqual((next_update - crl.last_update_utc).days, days)
            self.assertEqual(algorithm.name, digest)
            self.assertEqual(len(crl), 0)
        self.assertEqual(
            acquired[ca_lock_path(str(self.base), "authority", "__graph__")], 0
        )
        self.assertFalse(self.invoke()["changed"])

    def test_revocations_force_and_authority_independence(self) -> None:
        """Only the selected issuer changes; force still processes every authority."""
        self.assertTrue(self.invoke()["changed"])
        certificates = {p: p.read_bytes() for p in (self.base / "ca").glob("*.pem")}
        revoked = self.invoke(
            revocations={"issuer": [{"name": "leaf", "reason": "superseded"}]}
        )
        self.assertEqual(
            [item["changed"] for item in revoked["results"]], [True, False]
        )
        self.assertEqual(
            self.load_crl("issuer")[0].serial_number, self.leaf.serial_number
        )
        self.assertEqual(len(self.load_crl("root")), 0)
        self.assertFalse(self.invoke()["changed"])
        forced = self.invoke(force=True)
        self.assertTrue(all(item["changed"] for item in forced["results"]))
        self.assertEqual([item["crl_number"] for item in forced["results"]], [3, 2])
        self.assertFalse(self.invoke()["changed"])
        self.assertFalse(self.invoke(_ansible_check_mode=True)["changed"])
        self.assertEqual(certificates, {p: p.read_bytes() for p in certificates})

    def test_invalid_batch_before_writes(self) -> None:
        """Reject duplicate identities, malformed lists and invalid CRL policies."""
        invalid_window = copy.deepcopy(self.authorities)
        invalid_window[1]["crl_renew_before_days"] = 30
        invalid_digest = copy.deepcopy(self.authorities)
        invalid_digest[1]["crl_digest"] = "test-passphrase"
        cases = (
            {"authorities": self.authorities + self.authorities[:1]},
            {"authorities": invalid_window},
            {"authorities": invalid_digest},
            {"revocations": {"root": {"serial": "42"}}},
            {"revocations": {"root": ["not a mapping"]}},
        )
        for case in cases:
            with self.subTest(case=case):
                self.assertTrue(self.invoke(**case)["failed"])
                self.assertFalse((self.base / "crl").exists())
        self.assertFalse(self.invoke(authorities=[])["changed"])
        self.assertTrue(self.invoke(_ansible_check_mode=True)["changed"])
        self.assertFalse((self.base / "crl").exists())

    def test_rollover_and_archived_credentials(self) -> None:
        """Use explicit archived passwords and preserve all active CRL generations."""
        initial = self.invoke()
        old_id = initial["results"][0]["legacy_generation"]
        self.ca.authority(
            "issuer", "root", force=True, key_passphrase="rotated-crl-secret"
        )
        self.authorities[0].update(
            key_passphrase="rotated-crl-secret",
            archived_key_passphrases={old_id: "test-passphrase"},
            legacy_generation=old_id,
        )
        before = snapshot(self.base)
        with forbid_mutation():
            predicted = self.invoke(_ansible_check_mode=True)
        self.assertEqual(before, snapshot(self.base))
        result = self.invoke()
        self.assertTrue(result["changed"])
        self.assertEqual(
            predicted["results"][0]["generations"], result["results"][0]["generations"]
        )
        generations = result["results"][0]["generations"]
        self.assertEqual(len(generations), 2)
        self.assertTrue(all(not item["retired"] for item in generations.values()))
        self.assertTrue(all(item["crl_number"] == 2 for item in generations.values()))
        self.assertFalse(self.invoke()["changed"])
        self.authorities[0]["archived_key_passphrases"][old_id] = "wrong-crl-secret"
        self.assertFalse(self.invoke()["changed"])
        self.assertTrue(self.invoke(force=True)["failed"])
        self.authorities[0]["archived_key_passphrases"][old_id] = "test-passphrase"
        self.assertFalse(self.invoke()["changed"])
