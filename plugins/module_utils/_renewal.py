# Copyright (c) 2026 Jonas Mauer
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+
# (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Internal collection utility; not a public API.

Shared certificate renewal policy helpers for CA collection modules."""

from __future__ import annotations

import datetime as _dt
from typing import Any

from ansible_collections.jomrr.ca.plugins.module_utils._certificate_state import (
    CertificateOperation,
    RenewalDecision,
    RenewalPolicy,
)
from ansible_collections.jomrr.ca.plugins.module_utils._time import (
    certificate_not_valid_after,
    certificate_not_valid_before,
    now_utc,
    parse_datetime,
)

try:
    from cryptography import x509
except ImportError:
    pass


def _bool(value: Any) -> bool:
    """Return a predictable boolean for renewal policy values."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _int(value: Any, default: int = 0) -> int:
    """Return an integer with an empty-value default."""
    if value in (None, ""):
        return default
    return int(value)


def renewal_policy(value: object) -> RenewalPolicy:
    """Return normalized non-secret renewal policy values."""
    policy = value if isinstance(value, dict) else {}
    return {
        "warn_before_days": _int(policy.get("warn_before_days"), 0),
        "renew_before_days": _int(policy.get("renew_before_days"), 7),
        "renew_at": str(policy.get("renew_at") or ""),
        "rekey": _bool(policy.get("rekey", False)),
    }


def renewal_datetime(value: Any) -> _dt.datetime | None:
    """Parse an optional renewal timestamp."""
    return parse_datetime(value)


def renewal_decision(
    *,
    force: bool,
    not_before: _dt.datetime | None,
    not_after: _dt.datetime | None,
    policy_value: Any,
    now: _dt.datetime | None = None,
) -> RenewalDecision:
    """Return renewal and rekey decisions for an existing certificate."""
    policy = renewal_policy(policy_value)
    current_time = now if now is not None else now_utc()
    decision: RenewalDecision = {
        "renew": False,
        "rekey": False,
        "reason": "",
        "warning": False,
        "days_remaining": None,
        "policy": policy,
    }
    if force:
        decision.update({"renew": True, "rekey": True, "reason": "force"})
        return decision
    if not_before is None or not_after is None:
        decision["reason"] = "missing"
        return decision

    seconds_remaining = (not_after - current_time).total_seconds()
    decision["days_remaining"] = max(0, int(seconds_remaining // 86400))

    if policy["warn_before_days"] > 0:
        warning_at = not_after - _dt.timedelta(days=policy["warn_before_days"])
        decision["warning"] = current_time >= warning_at

    if not_after <= current_time:
        decision.update({"renew": True, "reason": "expired"})
    else:
        renew_at = renewal_datetime(policy["renew_at"])
        if renew_at is not None and not_before < renew_at <= current_time:
            decision.update({"renew": True, "reason": "scheduled"})
        elif policy["renew_before_days"] > 0:
            renew_window = not_after - _dt.timedelta(days=policy["renew_before_days"])
            if current_time >= renew_window:
                decision.update({"renew": True, "reason": "renewal_window"})

    if decision["renew"] and policy["rekey"]:
        decision["rekey"] = True
    return decision


def renewal_status(
    certificate: dict[str, Any],
    policy_value: Any,
    *,
    now: _dt.datetime | None = None,
) -> dict[str, Any]:
    """Return renewal status for a certificate summary and policy."""
    not_before = parse_datetime(certificate["not_valid_before"])
    not_after = parse_datetime(certificate["not_valid_after"])
    if not_before is None or not_after is None:
        raise ValueError("certificate summary must contain validity timestamps")
    decision = renewal_decision(
        force=False,
        not_before=not_before,
        not_after=not_after,
        policy_value=policy_value,
        now=now,
    )
    policy = decision["policy"]
    renew_at = renewal_datetime(policy["renew_at"])
    scheduled = renew_at is not None and not_before < renew_at
    state = {
        "expired": "expired",
        "scheduled": "scheduled_due",
        "renewal_window": "renewal_due",
    }.get(decision["reason"], "valid")
    if not decision["renew"]:
        if decision["warning"]:
            state = "warning"
        elif scheduled:
            state = "scheduled"
    return {
        "state": state,
        "days_remaining": decision["days_remaining"],
        "warning": decision["warning"],
        "renewal_due": decision["renew"],
        "scheduled": scheduled,
        "rekey_on_renewal": policy["rekey"],
        "policy": policy,
    }


def certificate_renewal(
    params: CertificateOperation, existing_cert: x509.Certificate | None
) -> RenewalDecision:
    """Return renewal and rekey decisions for an existing certificate."""
    if existing_cert is None:
        return renewal_decision(
            force=bool(params.request["force"]),
            not_before=None,
            not_after=None,
            policy_value=params.request["renewal"],
        )
    return renewal_decision(
        force=bool(params.request["force"]),
        not_before=certificate_not_valid_before(existing_cert),
        not_after=certificate_not_valid_after(existing_cert),
        policy_value=params.request["renewal"],
    )
