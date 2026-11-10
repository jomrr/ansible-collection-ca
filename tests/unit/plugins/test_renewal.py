# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
"""Issuance decisions and inventory status agree at renewal boundaries."""

from datetime import UTC, datetime, timedelta
from unittest import TestCase

from ansible_collections.jomrr.ca.plugins.module_utils._renewal import (
    renewal_decision,
    renewal_status,
)


class RenewalTests(TestCase):
    """Preserve scheduled, warning, force and missing-material semantics."""

    def test_status_and_decision_boundaries(self) -> None:
        """Compare both consumers with expected outcomes at fixed timestamps."""
        now = datetime(2026, 1, 15, tzinfo=UTC)
        before = now - timedelta(days=30)
        cases = (
            (0, "", "expired", "expired", True),
            (7, "", "renewal_window", "renewal_due", True),
            (14, "", "", "warning", True),
            (15, "", "", "valid", False),
            (30, now.isoformat(), "scheduled", "scheduled_due", False),
            (30, (now + timedelta(days=1)).isoformat(), "", "scheduled", False),
            (30, before.isoformat(), "", "valid", False),
        )
        for days, planned, reason, state, warning in cases:
            after = now + timedelta(days=days)
            policy = {
                "warn_before_days": 14,
                "renew_before_days": 7,
                "renew_at": planned,
                "rekey": True,
            }
            with self.subTest(days=days, planned=planned):
                decision = renewal_decision(
                    force=False,
                    not_before=before,
                    not_after=after,
                    policy_value=policy,
                    now=now,
                )
                status = renewal_status(
                    {"not_valid_before": before, "not_valid_after": after},
                    policy,
                    now=now,
                )
                self.assertEqual(decision["reason"], reason)
                self.assertEqual(status["state"], state)
                self.assertEqual(decision["renew"], bool(reason))
                self.assertEqual(decision["rekey"], bool(reason))
                self.assertEqual(status["renewal_due"], bool(reason))
                self.assertEqual(status["warning"], warning)
                self.assertEqual(decision["warning"], warning)
                self.assertEqual(status["days_remaining"], days)
                self.assertEqual(decision["days_remaining"], days)

    def test_missing_and_forced_material(self) -> None:
        """Force still requests a new key; absent material alone has no expiry."""
        for force, reason in ((False, "missing"), (True, "force")):
            with self.subTest(force=force):
                decision = renewal_decision(
                    force=force, not_before=None, not_after=None, policy_value={}
                )
                self.assertEqual(decision["reason"], reason)
                self.assertEqual(decision["renew"], force)
                self.assertEqual(decision["rekey"], force)
                self.assertFalse(decision["warning"])
                self.assertIsNone(decision["days_remaining"])
