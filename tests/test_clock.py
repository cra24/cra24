# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""The statutory clocks. A wrong deadline here is a missed legal obligation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cra24.clock import Track, Urgency, add_month, deadlines, parse, timeline
from cra24.errors import ConfigError

AWARE = "2026-09-17T08:30:00Z"
T0 = datetime(2026, 9, 17, 8, 30, tzinfo=timezone.utc)


def test_early_warning_is_24_hours_from_awareness() -> None:
    tl = timeline(AWARE)
    assert tl["early_warning"].due_at == T0 + timedelta(hours=24)


def test_notification_is_72_hours_from_awareness_not_from_submission() -> None:
    """The platform counter has been reported to run from submission. It is wrong."""
    tl = timeline(AWARE, submitted={"early_warning": "2026-09-18T07:00:00Z"})
    assert tl["notification"].due_at == T0 + timedelta(hours=72)
    assert tl["early_warning"].urgency() is Urgency.SUBMITTED


def test_vulnerability_final_report_runs_from_the_measure_not_from_awareness() -> None:
    tl = timeline(AWARE, measure_available_at="2026-09-25T00:00:00Z")
    assert tl["final_report"].due_at == datetime(2026, 10, 9, tzinfo=timezone.utc)


def test_vulnerability_final_report_has_no_clock_until_a_measure_exists() -> None:
    tl = timeline(AWARE)
    final = tl["final_report"]
    assert final.due_at is None
    assert final.urgency() is Urgency.NOT_STARTED
    assert "has not started" in final.basis


def test_incident_final_report_is_one_month_after_the_72_hour_notification() -> None:
    tl = timeline(AWARE, track=Track.INCIDENT)
    assert tl["final_report"].due_at == T0 + timedelta(hours=72) + timedelta(days=30)


def test_legal_basis_differs_by_track() -> None:
    assert timeline(AWARE)["early_warning"].legal_basis == "Article 14(1)(a)"
    assert timeline(AWARE, "incident")["early_warning"].legal_basis == "Article 14(3)(a)"


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        ("2026-09-17T09:00:00Z", Urgency.PENDING),
        ("2026-09-18T03:00:00Z", Urgency.DUE_SOON),  # inside the last quarter
        ("2026-09-18T09:00:00Z", Urgency.OVERDUE),
    ],
)
def test_early_warning_urgency(now: str, expected: Urgency) -> None:
    assert timeline(AWARE)["early_warning"].urgency(parse(now)) is expected


def test_next_due_is_the_soonest_unsubmitted() -> None:
    tl = timeline(AWARE)
    assert tl.next_due(parse("2026-09-17T09:00:00Z")).stage == "early_warning"


def test_worst_urgency_drives_the_headline() -> None:
    assert timeline(AWARE).worst_urgency(parse("2026-09-19T00:00:00Z")) is Urgency.OVERDUE


def test_naive_timestamps_are_read_as_utc() -> None:
    assert parse("2026-09-17T08:30:00") == T0


def test_offset_timestamps_are_honoured() -> None:
    assert parse("2026-09-17T10:30:00+02:00") == T0


@pytest.mark.parametrize("bad", ["", "not a date", "2026-13-45T99:99:99Z"])
def test_bad_timestamps_raise_a_readable_error(bad: str) -> None:
    with pytest.raises(ConfigError):
        parse(bad)


def test_flat_deadlines_shim_matches_the_timeline() -> None:
    flat = deadlines(AWARE, measure_available="2026-09-25T00:00:00Z")
    tl = timeline(AWARE, measure_available_at="2026-09-25T00:00:00Z")
    assert flat["early_warning_due"] == tl["early_warning"].due_at.isoformat()
    assert flat["final_report_due"] == tl["final_report"].due_at.isoformat()


class TestIncidentFinalReport:
    """Article 14(4): one month after the notification was *submitted*.

    Both halves of that sentence were wrong once. The window was 30 days rather
    than a calendar month, and it was measured from the 72-hour deadline rather
    than from the submission. Each mistake moves the deadline later than the law
    does, which is the direction that costs a filing.
    """

    def test_one_month_is_a_calendar_month_not_thirty_days(self) -> None:
        # 31 January + one month is the last day of February. +30 days is 2 March.
        tl = timeline(
            "2026-01-31T09:00:00Z",
            track=Track.INCIDENT,
            submitted={"notification": "2026-01-31T09:00:00Z"},
        )
        due = tl["final_report"].due_at
        assert due == datetime(2026, 2, 28, 9, 0, tzinfo=timezone.utc)
        assert due < datetime(2026, 1, 31, 9, 0, tzinfo=timezone.utc) + timedelta(days=30)

    def test_a_short_month_clamps_to_its_last_day(self) -> None:
        assert add_month(datetime(2026, 1, 30, 9, 0, tzinfo=timezone.utc)) == datetime(
            2026, 2, 28, 9, 0, tzinfo=timezone.utc
        )

    def test_it_runs_from_submission_when_the_notification_was_filed_early(self) -> None:
        early = timeline(
            "2026-01-31T09:00:00Z",
            track=Track.INCIDENT,
            submitted={"notification": "2026-01-31T12:00:00Z"},
        )
        assert early["final_report"].due_at == datetime(2026, 2, 28, 12, 0, tzinfo=timezone.utc)
        assert "submitted" in early["final_report"].basis

    def test_without_a_submission_time_it_assumes_the_latest_lawful_anchor(self) -> None:
        """No recorded submission means the deadline is the only anchor left."""
        tl = timeline("2026-01-31T09:00:00Z", track=Track.INCIDENT)
        assert tl["final_report"].due_at == add_month(
            datetime(2026, 1, 31, 9, 0, tzinfo=timezone.utc) + timedelta(hours=72)
        )
        assert "no submission time recorded" in tl["final_report"].basis
