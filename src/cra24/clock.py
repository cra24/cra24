# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""The statutory clocks of CRA Article 14.

Actively exploited vulnerability, Article 14(1) and 14(2):
  early warning   within 24 hours of becoming aware
  notification    within 72 hours of becoming aware
  final report    no later than 14 days after a corrective or mitigating
                  measure is available

Severe incident, Article 14(3) and 14(4):
  early warning   within 24 hours of becoming aware
  notification    within 72 hours of becoming aware
  final report    within one month of the 72-hour notification

Two operational notes that cost people deadlines:

1. The platform has been reported to display the 72-hour due date as 48 hours
   after the early warning was *submitted*, rather than 72 hours after you became
   *aware*. Those are different instants and the second one is the legal test.
   Trust this module, not the counter on the screen.
2. There is no platform counter at all for the vulnerability final report, because
   the deadline depends on when your fix ships. That clock starts when you set
   ``measure_available_at``, and nothing will remind you.

Verify against the regulation text before relying on any of this in anger.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

from .errors import ConfigError

EARLY_WARNING = timedelta(hours=24)
NOTIFICATION = timedelta(hours=72)
FINAL_VULN_AFTER_MEASURE = timedelta(days=14)
#: Nominal length of the incident final-report window, used only for the
#: ``DUE_SOON`` threshold. The deadline itself is a calendar month — see
#: :func:`add_month`.
FINAL_INCIDENT_AFTER_NOTIFICATION = timedelta(days=30)


def add_month(when: datetime) -> datetime:
    """Add one calendar month, the way EU time limits are counted.

    Regulation (EEC, Euratom) No 1182/71 Article 3(2)(c) counts a period in
    months to the day of the last month bearing the same number, and Article
    3(3) ends it on the last day of that month where no such day exists.

    Thirty days is not that. A notification submitted on 31 January is due on
    28 February, and ``+30 days`` says 2 March — two days after the deadline,
    in the direction where the tool tells you there is time left that the
    regulation does not give you.
    """
    year, month = when.year, when.month + 1
    if month > 12:
        year, month = year + 1, 1
    # 31 January + 1 month is the last day of February, not the 2nd or 3rd of March.
    day = min(when.day, calendar.monthrange(year, month)[1])
    return when.replace(year=year, month=month, day=day)


#: How long before a deadline the state flips to ``DUE_SOON``.
WARN_FRACTION = 0.25


class Track(str, Enum):
    VULNERABILITY = "vulnerability"
    INCIDENT = "incident"

    def __str__(self) -> str:
        return self.value


class Urgency(str, Enum):
    SUBMITTED = "submitted"
    NOT_STARTED = "not-started"
    PENDING = "pending"
    DUE_SOON = "due-soon"
    OVERDUE = "overdue"

    def __str__(self) -> str:
        return self.value


def parse(ts: str | datetime) -> datetime:
    """Parse an ISO 8601 instant. Naive input is read as UTC, loudly documented."""
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if not ts:
        raise ConfigError(
            "an empty timestamp was supplied", hint="use ISO 8601, e.g. 2026-09-17T08:30:00Z"
        )
    try:
        dt = datetime.fromisoformat(str(ts).strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConfigError(
            f"{ts!r} is not an ISO 8601 timestamp: {exc}",
            hint="e.g. 2026-09-17T08:30:00Z or 2026-09-17T10:30:00+02:00",
        ) from exc
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _fmt_delta(delta: timedelta) -> str:
    total = int(abs(delta).total_seconds())
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    text = " ".join(parts)
    return f"{text} overdue" if delta.total_seconds() < 0 else text


@dataclass
class Obligation:
    """One reporting stage with its deadline and current state."""

    stage: str
    label: str
    due_at: datetime | None
    basis: str
    legal_basis: str
    window: timedelta | None = None
    submitted_at: datetime | None = None

    def urgency(self, now: datetime | None = None) -> Urgency:
        if self.submitted_at is not None:
            return Urgency.SUBMITTED
        if self.due_at is None:
            return Urgency.NOT_STARTED
        now = now or datetime.now(timezone.utc)
        left = self.due_at - now
        if left.total_seconds() < 0:
            return Urgency.OVERDUE
        if self.window and left <= self.window * WARN_FRACTION:
            return Urgency.DUE_SOON
        return Urgency.PENDING

    def remaining(self, now: datetime | None = None) -> timedelta | None:
        if self.due_at is None:
            return None
        return self.due_at - (now or datetime.now(timezone.utc))

    def to_dict(self, now: datetime | None = None) -> dict:
        left = self.remaining(now)
        return {
            "stage": self.stage,
            "label": self.label,
            "due_at": self.due_at.isoformat() if self.due_at else None,
            "basis": self.basis,
            "legal_basis": self.legal_basis,
            "urgency": self.urgency(now).value,
            "remaining": _fmt_delta(left) if left is not None else None,
            "remaining_seconds": int(left.total_seconds()) if left is not None else None,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
        }


@dataclass
class Timeline:
    """All three obligations for one event."""

    aware_at: datetime
    track: Track
    obligations: list[Obligation]

    def __getitem__(self, stage: str) -> Obligation:
        for o in self.obligations:
            if o.stage == stage:
                return o
        raise KeyError(stage)

    def next_due(self, now: datetime | None = None) -> Obligation | None:
        pending = [
            o
            for o in self.obligations
            if o.due_at and o.urgency(now) not in (Urgency.SUBMITTED,)
        ]
        return min(pending, key=lambda o: o.due_at) if pending else None  # type: ignore[arg-type,return-value]

    def worst_urgency(self, now: datetime | None = None) -> Urgency:
        order = [
            Urgency.SUBMITTED,
            Urgency.NOT_STARTED,
            Urgency.PENDING,
            Urgency.DUE_SOON,
            Urgency.OVERDUE,
        ]
        return max(
            (o.urgency(now) for o in self.obligations),
            key=order.index,
            default=Urgency.NOT_STARTED,
        )

    def to_dict(self, now: datetime | None = None) -> dict:
        return {
            "aware_at": self.aware_at.isoformat(),
            "track": self.track.value,
            "evaluated_at": (now or datetime.now(timezone.utc)).isoformat(),
            "worst_urgency": self.worst_urgency(now).value,
            "obligations": [o.to_dict(now) for o in self.obligations],
        }


def timeline(
    aware_at: str | datetime,
    track: str | Track = Track.VULNERABILITY,
    measure_available_at: str | datetime | None = None,
    submitted: dict[str, str] | None = None,
) -> Timeline:
    """Build the full Article 14 timeline for one event.

    ``submitted`` maps a stage id to the instant you submitted it, so an already
    filed early warning stops showing as overdue.
    """
    t0 = parse(aware_at)
    track = Track(track) if isinstance(track, str) else track
    done = {k: parse(v) for k, v in (submitted or {}).items() if v}

    obligations = [
        Obligation(
            stage="early_warning",
            label="Early warning",
            due_at=t0 + EARLY_WARNING,
            window=EARLY_WARNING,
            basis="24 hours from becoming aware",
            legal_basis="Article 14(1)(a)"
            if track is Track.VULNERABILITY
            else "Article 14(3)(a)",
            submitted_at=done.get("early_warning"),
        ),
        Obligation(
            stage="notification",
            label="Notification with initial assessment",
            due_at=t0 + NOTIFICATION,
            window=NOTIFICATION,
            basis="72 hours from becoming aware",
            legal_basis="Article 14(1)(b)"
            if track is Track.VULNERABILITY
            else "Article 14(3)(b)",
            submitted_at=done.get("notification"),
        ),
    ]

    if track is Track.INCIDENT:
        # Article 14(4) runs from the *submission* of the notification, not from
        # the 72-hour deadline for it. File the notification early and the final
        # report is due earlier too; anchoring to the deadline would quietly
        # grant time the regulation does not.
        filed = done.get("notification")
        anchor = filed or (t0 + NOTIFICATION)
        basis = (
            "one month after the notification was submitted"
            if filed
            else "one month after the 72-hour notification deadline "
            "(no submission time recorded, so the latest lawful anchor is assumed)"
        )
        obligations.append(
            Obligation(
                stage="final_report",
                label="Final report",
                due_at=add_month(anchor),
                window=FINAL_INCIDENT_AFTER_NOTIFICATION,
                basis=basis,
                legal_basis="Article 14(4)",
                submitted_at=done.get("final_report"),
            )
        )
    elif measure_available_at:
        due = parse(measure_available_at) + FINAL_VULN_AFTER_MEASURE
        obligations.append(
            Obligation(
                stage="final_report",
                label="Final report",
                due_at=due,
                window=FINAL_VULN_AFTER_MEASURE,
                basis="14 days after the corrective or mitigating measure became available",
                legal_basis="Article 14(2)",
                submitted_at=done.get("final_report"),
            )
        )
    else:
        obligations.append(
            Obligation(
                stage="final_report",
                label="Final report",
                due_at=None,
                window=FINAL_VULN_AFTER_MEASURE,
                basis="14 days after a corrective or mitigating measure becomes available "
                "— no measure date recorded, so this clock has not started",
                legal_basis="Article 14(2)",
                submitted_at=done.get("final_report"),
            )
        )

    return Timeline(aware_at=t0, track=track, obligations=obligations)


def deadlines(
    aware_at: str, kind: str = "vulnerability", measure_available: str | None = None
) -> dict:
    """Flat dict form, kept for the 0.1 CLI surface and for simple templating."""
    tl = timeline(aware_at, track=kind, measure_available_at=measure_available)
    final = tl["final_report"]
    return {
        "aware_at": tl.aware_at.isoformat(),
        "early_warning_due": tl["early_warning"].due_at.isoformat(),  # type: ignore[union-attr]
        "notification_due": tl["notification"].due_at.isoformat(),  # type: ignore[union-attr]
        "final_report_due": final.due_at.isoformat() if final.due_at else None,
        "final_report_basis": final.basis,
    }


def remaining(aware_at: str, now: datetime | None = None) -> dict:
    tl = timeline(aware_at)
    return {
        "early_warning": tl["early_warning"].remaining(now),
        "notification": tl["notification"].remaining(now),
    }
