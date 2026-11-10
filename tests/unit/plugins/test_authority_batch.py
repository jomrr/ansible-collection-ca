# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Authority batches preserve issuance semantics with one graph lock."""

from __future__ import annotations

import copy
import fcntl
import json
import os
import shutil
from collections import Counter
from itertools import pairwise
from pathlib import Path
from tempfile import mkdtemp
from typing import Any
from unittest import TestCase
from unittest.mock import patch

from ansible_collections.jomrr.ca.plugins.module_utils._file import ca_lock_path
from ansible_collections.jomrr.ca.plugins.modules import authority_batch
from ansible_collections.jomrr.ca.tests.unit.plugins.module_fixture import (
    module_transport,
)
from cryptography import x509
from cryptography.x509.oid import NameOID


class AuthorityBatchTests(TestCase):
    """Exercise the public module through real argument loading and file writes."""

    def setUp(self) -> None:
        self.root = Path(mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.base = self.root / "pki"
        self.items: list[dict[str, Any]] = [
            {"name": "child", "parent": "parent", "subject": {"organization": "Child"}},
            {
                "name": "parent",
                "parent": "root",
                "basic_constraints": ["CA:TRUE", "pathlen:1"],
            },
            {"name": "sibling", "parent": "root"},
            {
                "name": "root",
                "parent": "root",
                "basic_constraints": ["CA:TRUE", "pathlen:2"],
            },
        ]
        for item in self.items:
            item.update(
                common_name=item["name"],
                days=365,
                key_type="P-256",
                key_passphrase=f"{item['name']}-batch-secret",
            )
        self.params: dict[str, Any] = {
            "base_dir": str(self.base),
            "base_url": "http://pki.example.test",
            "ca_name": "batch",
            "authorities": self.items,
            "subject": {"country": "DE", "organization": "Shared"},
            "renewal": {"renew_before_days": 0},
            "owner": str(os.getuid()),
            "group": str(os.getgid()),
        }

    def invoke(self, **overrides: Any) -> dict[str, Any]:
        """Run the real Ansible module, isolating only input transport and syslog."""
        inputs = {**copy.deepcopy(self.params), **overrides}
        with (
            module_transport(inputs) as (output, log),
            self.assertRaises(SystemExit),
        ):
            authority_batch.main()
        emitted = output.getvalue() + str(log.call_args_list)
        for item in self.items:
            self.assertNotIn(item["key_passphrase"], emitted)
        result: dict[str, Any] = json.loads(output.getvalue())
        return result

    def test_parent_order_and_one_graph_lock(self) -> None:
        """Create a reversed graph with distinct credentials and inspect real locks."""
        acquired: Counter[str] = Counter()
        flock = fcntl.flock

        def record_lock(fd: int, operation: int) -> None:
            if operation == fcntl.LOCK_EX:
                acquired[os.readlink(f"/proc/self/fd/{fd}")] += 1
                operation |= fcntl.LOCK_NB
            flock(fd, operation)

        with patch.object(fcntl, "flock", side_effect=record_lock):
            result = self.invoke()
        self.assertNotIn("failed", result)
        self.assertTrue(result["changed"])
        self.assertEqual(result["count"], 4)
        names = [item["name"] for item in result["results"]]
        for item in self.items:
            self.assertLessEqual(names.index(item["parent"]), names.index(item["name"]))
        self.assertEqual(
            acquired[ca_lock_path(str(self.base), "authority", "__graph__")], 1
        )
        for item in self.items:
            self.assertEqual(
                acquired[ca_lock_path(str(self.base), "authority", item["name"])], 1
            )
        child = x509.load_pem_x509_certificate(
            (self.base / "ca/child-ca.pem").read_bytes()
        )
        self.assertEqual(
            child.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value, "DE"
        )
        self.assertEqual(
            child.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value,
            "Child",
        )
        chain = x509.load_pem_x509_certificates(
            (self.base / "chains/child-ca-chain.pem").read_bytes()
        )
        self.assertEqual(len(chain), 3)
        for cert, issuer in pairwise(chain):
            cert.verify_directly_issued_by(issuer)
        self.assertFalse((self.base / "chains/root-ca-chain.pem").exists())
        self.assertFalse(self.invoke()["changed"])
        original_root = (self.base / "ca/root-ca.pem").read_bytes()
        self.items[-1]["key_passphrase"] = "wrong-root-batch-secret"
        failed = self.invoke()
        self.assertTrue(failed["failed"])
        self.assertEqual((self.base / "ca/root-ca.pem").read_bytes(), original_root)

    def test_chain_repair_subject_update_and_force(self) -> None:
        """Repair exports without reissuing, then update and force the same graph."""
        self.assertTrue(self.invoke()["changed"])
        certificate = self.base / "ca/child-ca.pem"
        original = certificate.read_bytes()
        chain = self.base / "chains/child-ca-chain.der"
        chain.write_bytes(b"altered")
        stale = self.base / "chains/root-ca-chain.pem"
        stale.write_bytes(b"stale root chain")
        repaired = self.invoke()
        self.assertTrue(repaired["changed"])
        self.assertEqual(certificate.read_bytes(), original)
        self.assertFalse(stale.exists())
        self.assertNotEqual(chain.read_bytes(), b"altered")
        self.assertTrue(
            next(item for item in repaired["results"] if item["name"] == "child")[
                "chain_changed"
            ]
        )
        self.assertFalse(self.invoke()["changed"])
        self.items[0]["subject"] = {"organization": "Updated"}
        self.assertTrue(self.invoke()["changed"])
        self.assertNotEqual(certificate.read_bytes(), original)
        self.assertFalse(self.invoke()["changed"])
        root = self.base / "ca/root-ca.pem"
        original_root = root.read_bytes()
        self.assertTrue(self.invoke(force=True)["changed"])
        self.assertNotEqual(root.read_bytes(), original_root)
        self.assertFalse(self.invoke()["changed"])

    def test_cycle_rejected_before_writes(self) -> None:
        """All names exist, but a parent cycle must fail before creating CA state."""
        self.items[-1]["parent"] = "child"
        result = self.invoke()
        self.assertTrue(result["failed"])
        self.assertIn("cycle", result["msg"])
        self.assertFalse(self.base.exists())

    def test_empty_check_mode_and_invalid_secret_input(self) -> None:
        """Empty/check runs do not write; invalid arguments keep credentials masked."""
        result = self.invoke(authorities=[])
        self.assertFalse(result["changed"])
        self.assertEqual(result["results"], [])
        self.assertFalse(self.base.exists())
        self.assertTrue(self.invoke(_ansible_check_mode=True)["skipped"])
        self.assertFalse(self.base.exists())
        failed = self.invoke(force="invalid-" + self.items[0]["key_passphrase"])
        self.assertTrue(failed["failed"])
        self.assertFalse(self.base.exists())
