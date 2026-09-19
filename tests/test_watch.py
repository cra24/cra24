# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Watch mode.

The tests that matter here are about restraint: firing once, never moving a
clock that has started, and surviving a bad product file or a dead webhook.
A watcher that is noisy or that rewrites timestamps is worse than none.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cra24.feeds import FeedSet
from cra24.model import Product
from cra24.notify import Alert, FileNotifier, StdoutNotifier, build, send_all
from cra24.watch import State, Tracked, candidate_cves, load_products, run_once

T0 = datetime(2026, 9, 18, 3, 14, tzinfo=timezone.utc)


@pytest.fixture
def products_dir(tmp_path: Path, product: Product) -> Path:
    directory = tmp_path / "products"
    directory.mkdir()
    product.save(directory / "acmegateway.json")
    return directory


class TestCandidateSelection:
    def test_only_unpatched_and_unknown_are_checked(self, product: Product) -> None:
        """A CVE the layer patched does not become reportable because CISA
        listed it — you are not affected by it."""
        cves = candidate_cves(product)
        assert "CVE-2024-1086" in cves  # unpatched
        assert "CVE-2024-0727" not in cves  # patched
        assert "CVE-2023-42364" not in cves  # ignored

    def test_all_cves_can_be_forced(self, product: Product) -> None:
        assert "CVE-2024-0727" in candidate_cves(product, include_all=True)


class TestFiringOnce:
    def test_the_first_pass_alerts(
        self, products_dir: Path, offline_feeds: FeedSet, tmp_path: Path
    ) -> None:
        result = run_once(products_dir, feeds=offline_feeds, dossier_root=tmp_path / "d")
        assert result.alerts
        assert any(a.reportable for a in result.alerts)

    def test_the_second_pass_is_silent(
        self, products_dir: Path, offline_feeds: FeedSet, tmp_path: Path
    ) -> None:
        """A watcher that re-sends every quarter-hour trains people to filter it,
        and then the one that mattered is filtered too."""
        run_once(products_dir, feeds=offline_feeds, dossier_root=tmp_path / "d")
        second = run_once(products_dir, feeds=offline_feeds, dossier_root=tmp_path / "d")
        assert second.alerts == []
        assert second.skipped_unchanged > 0

    def test_state_records_one_notification_per_finding(
        self, products_dir: Path, offline_feeds: FeedSet, tmp_path: Path
    ) -> None:
        run_once(products_dir, feeds=offline_feeds, dossier_root=tmp_path / "d")
        run_once(products_dir, feeds=offline_feeds, dossier_root=tmp_path / "d")
        state = State(products_dir / "watch-state.json")
        assert state.entries
        assert all(e.notify_count == 1 for e in state.entries.values())


class TestTheClock:
    def test_awareness_is_stamped_at_first_detection(
        self, products_dir: Path, offline_feeds: FeedSet, tmp_path: Path
    ) -> None:
        run_once(products_dir, feeds=offline_feeds, dossier_root=tmp_path / "d", now=T0)
        entry = State(products_dir / "watch-state.json").get("AcmeGateway", "CVE-2024-1086")
        assert entry.became_aware_at == T0.isoformat(timespec="seconds")

    def test_awareness_is_never_rewritten_on_a_later_pass(
        self, products_dir: Path, offline_feeds: FeedSet, tmp_path: Path
    ) -> None:
        """The one error here with legal consequences.

        Article 14 runs from awareness. A tool that refreshed the timestamp on
        every poll would produce a dossier understating how long you have known.
        """
        run_once(products_dir, feeds=offline_feeds, dossier_root=tmp_path / "d", now=T0)
        later = T0 + timedelta(days=3)
        run_once(products_dir, feeds=offline_feeds, dossier_root=tmp_path / "d", now=later)
        entry = State(products_dir / "watch-state.json").get("AcmeGateway", "CVE-2024-1086")
        assert entry.became_aware_at == T0.isoformat(timespec="seconds")

    def test_the_alert_carries_the_early_warning_deadline(
        self, products_dir: Path, offline_feeds: FeedSet, tmp_path: Path
    ) -> None:
        result = run_once(
            products_dir, feeds=offline_feeds, dossier_root=tmp_path / "d", now=T0
        )
        alert = next(a for a in result.alerts if a.reportable)
        assert alert.early_warning_due.startswith("2026-09-19T03:14")


class TestDossiers:
    def test_a_dossier_is_written_for_every_alert(
        self, products_dir: Path, offline_feeds: FeedSet, tmp_path: Path
    ) -> None:
        """The point of the whole thing: what reaches you is a draft, not an alert."""
        result = run_once(products_dir, feeds=offline_feeds, dossier_root=tmp_path / "d")
        for alert in result.alerts:
            assert alert.dossier_path
            assert Path(alert.dossier_path).is_file()

    def test_the_watcher_writes_a_verifiable_evidence_chain(
        self, products_dir: Path, offline_feeds: FeedSet, tmp_path: Path
    ) -> None:
        from cra24.evidence import Ledger

        run_once(products_dir, feeds=offline_feeds, dossier_root=tmp_path / "d")
        ok, messages = Ledger(tmp_path / "d" / "acmegateway" / "evidence").verify()
        assert ok, messages

    def test_dossiers_can_be_turned_off(
        self, products_dir: Path, offline_feeds: FeedSet, tmp_path: Path
    ) -> None:
        result = run_once(
            products_dir, feeds=offline_feeds, dossier_root=tmp_path / "d", write_dossiers=False
        )
        assert all(a.dossier_path == "" for a in result.alerts)


class TestResilience:
    def test_a_malformed_product_file_is_skipped_not_fatal(
        self, products_dir: Path, offline_feeds: FeedSet, tmp_path: Path
    ) -> None:
        (products_dir / "broken.json").write_text("{not json")
        result = run_once(products_dir, feeds=offline_feeds, dossier_root=tmp_path / "d")
        assert result.checked_products == 1
        assert result.alerts

    def test_no_products_at_all_is_an_actionable_error(self, tmp_path: Path) -> None:
        from cra24.errors import ConfigError

        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(ConfigError) as excinfo:
            load_products(empty)
        assert "cra24 scan" in str(excinfo.value)

    def test_corrupt_state_says_what_to_do(self, tmp_path: Path) -> None:
        from cra24.errors import ConfigError

        path = tmp_path / "watch-state.json"
        path.write_text("{oh no")
        with pytest.raises(ConfigError) as excinfo:
            State(path)
        assert "delete it" in str(excinfo.value)

    def test_a_failing_notifier_does_not_stop_the_others(self) -> None:
        class Broken:
            name = "broken"

            def send(self, alert: Alert) -> bool:
                raise RuntimeError("webhook is down")

        alert = Alert(
            product="X",
            product_version="1",
            cve="CVE-2026-1",
            status="affected",
            reportable=True,
            summary="s",
            detected_at=T0.isoformat(),
        )
        target = []

        class Recording:
            name = "recording"

            def send(self, a: Alert) -> bool:
                target.append(a)
                return True

        assert send_all([Broken(), Recording()], alert) == 1
        assert target


class TestNotifiers:
    def test_a_reportable_alert_leads_with_the_clock(self) -> None:
        alert = Alert(
            product="Gateway",
            product_version="2.4.0",
            cve="CVE-2026-1",
            status="affected",
            reportable=True,
            summary="exploited",
            detected_at="2026-09-18T03:14:00+00:00",
            early_warning_due="2026-09-19T03:14:00+00:00",
            remaining="20h 1m",
            gaps=["severity — Severity level"],
        )
        text = alert.to_text()
        assert "ACTION REQUIRED" in text
        assert "ARTICLE 14(1) CLOCK" in text
        assert "STILL NEEDED FROM A HUMAN (1)" in text
        assert "not affiliated" in text.lower()

    def test_a_non_reportable_alert_says_no_clock_started(self) -> None:
        alert = Alert(
            product="Gateway",
            product_version="2.4.0",
            cve="CVE-2026-1",
            status="affected",
            reportable=False,
            summary="unpatched",
            detected_at="2026-09-18T03:14:00+00:00",
        )
        assert "No clock has been started" in alert.to_text()

    def test_the_file_notifier_appends_json_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "alerts.jsonl"
        notifier = FileNotifier(path)
        alert = Alert(
            product="X",
            product_version="1",
            cve="CVE-2026-1",
            status="affected",
            reportable=True,
            summary="s",
            detected_at=T0.isoformat(),
        )
        assert notifier.send(alert)
        assert notifier.send(alert)
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["cve"] == "CVE-2026-1"

    @pytest.mark.parametrize(
        ("spec", "expected"),
        [
            ("stdout", "stdout"),
            ("", "stdout"),
            ("file:/tmp/x.jsonl", "file"),
            ("webhook:https://example.invalid/hook", "webhook"),
            ("https://example.invalid/hook", "webhook"),
            ("email:psirt@example.invalid", "email"),
        ],
    )
    def test_notifier_specs_parse(self, spec: str, expected: str) -> None:
        assert build(spec).name == expected

    def test_an_unknown_spec_lists_the_valid_ones(self) -> None:
        from cra24.errors import ConfigError

        with pytest.raises(ConfigError) as excinfo:
            build("carrier-pigeon:bob")
        assert "webhook:URL" in str(excinfo.value)

    def test_the_default_notifier_prints(self, capsys: pytest.CaptureFixture) -> None:
        StdoutNotifier().send(
            Alert(
                product="X",
                product_version="1",
                cve="CVE-2026-1",
                status="affected",
                reportable=False,
                summary="s",
                detected_at=T0.isoformat(),
            )
        )
        assert "CVE-2026-1" in capsys.readouterr().out


def test_state_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    state = State(path)
    state.put(
        Tracked(
            product="X", cve="CVE-2026-1", became_aware_at=T0.isoformat(), last_reportable=True
        )
    )
    state.save()
    reloaded = State(path)
    assert reloaded.get("X", "CVE-2026-1").became_aware_at == T0.isoformat()
    assert len(reloaded.open_findings()) == 1
