# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""The evidence ledger. These are the tests an auditor would want to see run."""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from cra24.evidence import GENESIS, KEY_ENV, Ledger


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    (tmp_path / "a.json").write_text('{"x": 1}')
    (tmp_path / "b.md").write_text("hello")
    led = Ledger(tmp_path / "evidence")
    led.append("dossier", [tmp_path / "a.json"], {"cve": "CVE-2026-1"})
    led.append("dossier", [tmp_path / "b.md"], {"cve": "CVE-2026-1"})
    return led


def test_a_fresh_chain_verifies(ledger: Ledger) -> None:
    ok, messages = ledger.verify()
    assert ok
    assert "chain intact over 2 records" in messages[0]


def test_the_first_record_links_to_genesis(ledger: Ledger) -> None:
    assert ledger.records()[0].prev == GENESIS


def test_records_are_sequenced(ledger: Ledger) -> None:
    assert [r.seq for r in ledger.records()] == [0, 1]


def test_editing_an_artefact_is_detected(ledger: Ledger, tmp_path: Path) -> None:
    (tmp_path / "b.md").write_text("tampered")
    ok, messages = ledger.verify()
    assert not ok
    assert "has changed since it was recorded" in messages[0]


def test_deleting_an_artefact_is_detected(ledger: Ledger, tmp_path: Path) -> None:
    (tmp_path / "a.json").unlink()
    ok, messages = ledger.verify()
    assert not ok
    assert "missing" in messages[0]


def test_editing_a_ledger_record_breaks_the_chain(ledger: Ledger) -> None:
    lines = ledger.path.read_text().splitlines()
    record = json.loads(lines[0])
    record["meta"]["cve"] = "CVE-2026-9999"
    lines[0] = json.dumps(record, sort_keys=True)
    ledger.path.write_text("\n".join(lines) + "\n")
    ok, messages = ledger.verify()
    assert not ok
    assert "chain broken" in messages[0]


def test_removing_a_record_breaks_the_chain(ledger: Ledger) -> None:
    lines = ledger.path.read_text().splitlines()
    ledger.path.write_text(lines[1] + "\n")
    assert not ledger.verify()[0]


def test_chain_only_skips_re_hashing_the_files(ledger: Ledger, tmp_path: Path) -> None:
    (tmp_path / "b.md").write_text("tampered")
    assert ledger.verify(check_files=False)[0] is True
    assert ledger.verify(check_files=True)[0] is False


def test_an_empty_ledger_does_not_pass(tmp_path: Path) -> None:
    assert Ledger(tmp_path / "nothing").verify()[0] is False


class TestHmac:
    def test_hmac_is_written_and_verified(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(KEY_ENV, "deadbeef")
        (tmp_path / "a.json").write_text("{}")
        led = Ledger(tmp_path / "ev")
        led.append("x", [tmp_path / "a.json"])
        ok, messages = led.verify()
        assert ok
        assert "HMAC verified" in messages[-1]

    def test_an_edit_defeats_the_hmac(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(KEY_ENV, "deadbeef")
        (tmp_path / "a.json").write_text("{}")
        led = Ledger(tmp_path / "ev")
        led.append("x", [tmp_path / "a.json"])
        record = json.loads(led.path.read_text().splitlines()[0])
        record["meta"] = {"evil": True}
        led.path.write_text(json.dumps(record, sort_keys=True) + "\n")
        ok, messages = led.verify()
        assert not ok
        assert "HMAC does not match" in messages[0]

    def test_an_hmac_without_a_key_is_reported_not_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(KEY_ENV, "deadbeef")
        (tmp_path / "a.json").write_text("{}")
        led = Ledger(tmp_path / "ev")
        led.append("x", [tmp_path / "a.json"])
        monkeypatch.delenv(KEY_ENV)
        ok, messages = led.verify()
        assert not ok
        assert "no key is configured" in messages[0]


def test_summary_reports_the_head(ledger: Ledger) -> None:
    summary = ledger.summary()
    assert summary["records"] == 2
    assert summary["head"] == ledger.head()
    assert summary["artefacts"] == 2


class TestTailRead:
    """append() reads the last record instead of the whole ledger.

    It needs two facts — the sequence number and the previous digest — and both
    are on the final line. Reading the file to find them made every append cost
    the length of the whole history.
    """

    def _ledger(self, tmp_path: Path, records: int) -> Ledger:
        ledger = Ledger(tmp_path / "evidence")
        for i in range(records):
            ledger.append(f"event-{i}", meta={"i": i})
        return ledger

    def test_the_tail_agrees_with_a_full_read(self, tmp_path: Path) -> None:
        ledger = self._ledger(tmp_path, 12)
        assert ledger._last_record().to_dict() == ledger.records()[-1].to_dict()
        assert ledger.head() == ledger.records()[-1].digest

    def test_a_record_longer_than_the_read_window_is_still_whole(self, tmp_path: Path) -> None:
        """The window starts at 4 KiB and must grow until the line is complete."""
        ledger = Ledger(tmp_path / "evidence")
        ledger.append("small", meta={"note": "first"})
        ledger.append("huge", meta={"padding": "x" * 20_000})
        last = ledger._last_record()
        assert last is not None
        assert last.event == "huge"
        assert last.meta["padding"] == "x" * 20_000
        assert last.to_dict() == ledger.records()[-1].to_dict()

    def test_sequence_and_linkage_survive_the_optimisation(self, tmp_path: Path) -> None:
        ledger = self._ledger(tmp_path, 5)
        records = ledger.records()
        assert [r.seq for r in records] == [0, 1, 2, 3, 4]
        assert records[0].prev == GENESIS
        for earlier, later in itertools.pairwise(records):
            assert later.prev == earlier.digest
        ok, _ = ledger.verify(check_files=False)
        assert ok

    def test_an_empty_ledger_reports_genesis(self, tmp_path: Path) -> None:
        assert Ledger(tmp_path / "nothing").head() == GENESIS


class TestExpectHead:
    """Truncation leaves a shorter chain that is still internally consistent.

    Nothing inside the ledger can catch that, which is why the head hash is
    meant to be anchored somewhere else. --expect-head makes the anchor
    checkable rather than advisory.
    """

    def test_the_anchored_head_passes(self, tmp_path: Path) -> None:
        ledger = Ledger(tmp_path / "evidence")
        ledger.append("one")
        ledger.append("two")
        ok, messages = ledger.verify(check_files=False, expect_head=ledger.head())
        assert ok
        assert any("matches the anchor" in m for m in messages)

    def test_a_truncated_ledger_verifies_clean_without_the_anchor(self, tmp_path: Path) -> None:
        """The gap this closes: on its own, truncation is invisible."""
        ledger = Ledger(tmp_path / "evidence")
        ledger.append("one")
        ledger.append("two")
        lines = ledger.path.read_text().splitlines()
        ledger.path.write_text(lines[0] + "\n")
        ok, _ = ledger.verify(check_files=False)
        assert ok, "a truncated chain is still internally consistent"

    def test_but_is_caught_against_the_anchor(self, tmp_path: Path) -> None:
        ledger = Ledger(tmp_path / "evidence")
        ledger.append("one")
        ledger.append("two")
        anchored = ledger.head()
        lines = ledger.path.read_text().splitlines()
        ledger.path.write_text(lines[0] + "\n")
        ok, problems = ledger.verify(check_files=False, expect_head=anchored)
        assert not ok
        assert any("does not end where it should" in p for p in problems)


class TestKeyInfo:
    def test_an_unset_key_is_reported_as_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cra24.evidence import key_info

        monkeypatch.delenv(KEY_ENV, raising=False)
        assert key_info() == {"set": False}

    def test_a_hex_passphrase_is_reported_as_the_bytes_it_really_is(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ "deadbeef" looks like 8 characters and is 4 bytes of key material."""
        from cra24.evidence import key_info

        monkeypatch.setenv(KEY_ENV, "deadbeef")
        info = key_info()
        assert info["decoded_as"] == "hex"
        assert info["bytes"] == 4
        assert info["weak"] is True

    def test_a_real_key_is_not_flagged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from cra24.evidence import key_info

        monkeypatch.setenv(KEY_ENV, "ab" * 32)
        info = key_info()
        assert info["bytes"] == 32
        assert info["weak"] is False

    def test_text_that_is_not_hex_is_used_as_text(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cra24.evidence import key_info

        monkeypatch.setenv(KEY_ENV, "correct horse battery staple")
        info = key_info()
        assert info["decoded_as"] == "utf-8 text"
        assert info["weak"] is False
