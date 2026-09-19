# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""End-to-end CLI behaviour, including the exit codes a CI job depends on."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cra24.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
AWARE = "2026-09-17T08:30:00Z"


@pytest.fixture
def scanned(tmp_path: Path) -> Path:
    out = tmp_path / "product.json"
    assert (
        main(
            [
                "scan",
                "--build-dir",
                str(FIXTURES / "yocto-build"),
                "--config",
                str(FIXTURES / "demo-config.json"),
                "--out",
                str(out),
            ]
        )
        == 0
    )
    return out


class TestScan:
    def test_scan_writes_a_loadable_inventory(self, scanned: Path) -> None:
        data = json.loads(scanned.read_text())
        assert data["name"] == "AcmeGateway"
        assert any(c["name"] == "busybox" for c in data["components"])

    def test_two_sources_at_once_is_refused(self, tmp_path: Path) -> None:
        assert (
            main(
                [
                    "scan",
                    "--build-dir",
                    str(FIXTURES / "yocto-build"),
                    "--sbom",
                    str(FIXTURES / "sbom-spdx.json"),
                    "--out",
                    str(tmp_path / "p.json"),
                ]
            )
            == 3
        )

    def test_no_source_at_all_is_refused_with_a_hint(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        assert main(["scan"]) == 3
        assert "--build-dir" in capsys.readouterr().err


class TestCheck:
    def test_json_output_is_machine_readable(
        self, scanned: Path, capsys: pytest.CaptureFixture
    ) -> None:
        assert main(["check", "--product", str(scanned), "CVE-2024-1086", "--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "affected"
        assert payload["components"][0]["findings"]

    def test_gating_flag_accepts_bare_symbol_names(
        self, scanned: Path, capsys: pytest.CaptureFixture
    ) -> None:
        main(["check", "--product", str(scanned), "CVE-2024-1086", "--gate", "KSMBD", "--json"])
        assert json.loads(capsys.readouterr().out)["status"] == "not_affected"

    def test_gating_flag_accepts_several_symbols(
        self, scanned: Path, capsys: pytest.CaptureFixture
    ) -> None:
        main(
            [
                "check",
                "--product",
                str(scanned),
                "CVE-2024-1086",
                "--gate",
                "CONFIG_KSMBD,CONFIG_IP_VS",
                "--json",
            ]
        )
        assert json.loads(capsys.readouterr().out)["status"] == "not_affected"


class TestReport:
    def test_a_complete_dossier_exits_zero_and_writes_five_artefacts(
        self, scanned: Path, tmp_path: Path
    ) -> None:
        out = tmp_path / "dossier"
        code = main(
            [
                "report",
                "--product",
                str(scanned),
                "CVE-2024-1086",
                "--aware-at",
                AWARE,
                "--actively-exploited",
                "yes",
                "--severity",
                "high",
                "--summary",
                "Exploited in the wild.",
                "--out",
                str(out),
            ]
        )
        assert code == 0
        names = {p.name for p in out.glob("*")}
        assert "cve-2024-1086-early-warning.json" in names
        assert "cve-2024-1086-early-warning.md" in names
        assert "cve-2024-1086.csaf.json" in names
        assert "cve-2024-1086.openvex.json" in names
        assert (out / "evidence" / "ledger.jsonl").is_file()

    def test_an_incomplete_dossier_exits_six_but_still_writes(self, tmp_path: Path) -> None:
        """A CI job must be able to tell 'not ready' from 'crashed'."""
        out = tmp_path / "dossier"
        code = main(
            [
                "report",
                "--build-dir",
                str(FIXTURES / "yocto-build"),
                "CVE-2024-1086",
                "--aware-at",
                AWARE,
                "--out",
                str(out),
            ]
        )
        assert code == 6
        assert (out / "cve-2024-1086-early-warning.md").is_file()

    def test_the_evidence_ledger_verifies_after_a_report(
        self, scanned: Path, tmp_path: Path
    ) -> None:
        out = tmp_path / "dossier"
        main(
            [
                "report",
                "--product",
                str(scanned),
                "CVE-2024-1086",
                "--aware-at",
                AWARE,
                "--summary",
                "s",
                "--severity",
                "high",
                "--out",
                str(out),
            ]
        )
        assert main(["verify", str(out / "evidence")]) == 0

    def test_tampering_with_an_artefact_fails_verification(
        self, scanned: Path, tmp_path: Path
    ) -> None:
        out = tmp_path / "dossier"
        main(
            [
                "report",
                "--product",
                str(scanned),
                "CVE-2024-1086",
                "--aware-at",
                AWARE,
                "--summary",
                "s",
                "--severity",
                "high",
                "--out",
                str(out),
            ]
        )
        advisory = out / "cve-2024-1086.csaf.json"
        advisory.write_text(advisory.read_text().replace("Acme", "Someone Else"))
        assert main(["verify", str(out / "evidence")]) == 1

    def test_arbitrary_fields_can_be_answered_from_the_command_line(
        self, scanned: Path, tmp_path: Path
    ) -> None:
        out = tmp_path / "dossier"
        main(
            [
                "report",
                "--product",
                str(scanned),
                "CVE-2024-1086",
                "--aware-at",
                AWARE,
                "--summary",
                "s",
                "--field",
                "attack_vector=network",
                "--field",
                "euvd_id=EUVD-2026-1",
                "--out",
                str(out),
            ]
        )
        dossier = json.loads((out / "cve-2024-1086-early-warning.json").read_text())
        assert dossier["srp_fields"]["attack_vector"] == "network"
        assert dossier["srp_fields"]["euvd_id"] == "EUVD-2026-1"

    def test_a_malformed_field_argument_is_refused(self, scanned: Path, tmp_path: Path) -> None:
        assert (
            main(
                [
                    "report",
                    "--product",
                    str(scanned),
                    "CVE-2024-1086",
                    "--aware-at",
                    AWARE,
                    "--field",
                    "nonsense",
                    "--out",
                    str(tmp_path / "d"),
                ]
            )
            == 3
        )


class TestClock:
    def test_clock_json(self, capsys: pytest.CaptureFixture) -> None:
        assert main(["clock", "--aware-at", AWARE, "--json"]) in (0, 1)
        payload = json.loads(capsys.readouterr().out)
        assert payload["obligations"][0]["stage"] == "early_warning"

    def test_an_overdue_clock_exits_nonzero(self) -> None:
        """So a cron job can alert on it without parsing text."""
        assert main(["clock", "--aware-at", "2020-01-01T00:00:00Z"]) == 1

    def test_a_bad_timestamp_exits_three(self, capsys: pytest.CaptureFixture) -> None:
        assert main(["clock", "--aware-at", "yesterday"]) == 3
        assert "ISO 8601" in capsys.readouterr().err


class TestInitAndIntrospection:
    def test_init_writes_a_valid_template(self, tmp_path: Path) -> None:
        from cra24 import config as config_mod

        out = tmp_path / "cra24.json"
        assert main(["init", "--out", str(out)]) == 0
        assert config_mod.validate_config(json.loads(out.read_text())) == []

    def test_init_refuses_to_clobber(self, tmp_path: Path) -> None:
        out = tmp_path / "cra24.json"
        main(["init", "--out", str(out)])
        assert main(["init", "--out", str(out)]) == 3
        assert main(["init", "--out", str(out), "--force"]) == 0

    def test_spec_prints_the_field_set(self, capsys: pytest.CaptureFixture) -> None:
        assert main(["spec", "--stage", "early_warning"]) == 0
        assert "became_aware_at" in capsys.readouterr().out

    def test_spec_json_round_trips(self, capsys: pytest.CaptureFixture) -> None:
        assert main(["spec", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["spec_version"]

    def test_doctor_reports_the_installation(self, capsys: pytest.CaptureFixture) -> None:
        main(["doctor"])
        out = capsys.readouterr().out
        assert "srp field spec" in out
        assert "csaf_json_schema.json" in out


class TestGlobalFlags:
    def test_verbose_works_before_the_subcommand(self, scanned: Path) -> None:
        assert main(["-v", "check", "--product", str(scanned), "CVE-2024-1086"]) == 0

    def test_verbose_works_after_the_subcommand(self, scanned: Path) -> None:
        assert main(["check", "--product", str(scanned), "CVE-2024-1086", "-v"]) == 0


class TestFeedsCommand:
    def test_status_lists_every_feed_and_its_host(
        self, capsys: pytest.CaptureFixture, tmp_path: Path
    ) -> None:
        assert (
            main(["feeds", "status", "--offline", "--cache-dir", str(tmp_path / "empty")]) == 0
        )
        out = capsys.readouterr().out
        for host in (
            "www.cisa.gov",
            "epss.cyentia.com",
            "api.osv.dev",
            "services.nvd.nist.gov",
            "euvdservices.enisa.europa.eu",
        ):
            assert host in out, f"{host} is not named in feeds status"

    def test_status_names_the_hosts_before_any_socket_is_opened(
        self, capsys: pytest.CaptureFixture, tmp_path: Path
    ) -> None:
        """A user must be able to see what will be contacted without contacting it."""
        main(["feeds", "status", "--offline", "--cache-dir", str(tmp_path / "e")])
        assert "not cached" in capsys.readouterr().out

    def test_terms_of_use_are_printed_on_request(
        self, capsys: pytest.CaptureFixture, tmp_path: Path
    ) -> None:
        main(["feeds", "status", "--offline", "--terms", "--cache-dir", str(tmp_path / "e")])
        out = capsys.readouterr().out
        assert "terms of use" in out
        assert "FIRST" in out

    def test_json_output(self, capsys: pytest.CaptureFixture, tmp_path: Path) -> None:
        assert (
            main(["feeds", "status", "--offline", "--json", "--cache-dir", str(tmp_path / "e")])
            == 0
        )
        payload = json.loads(capsys.readouterr().out)
        assert {e["name"] for e in payload} >= {"kev", "epss", "osv", "nvd", "euvd"}

    def test_sync_while_offline_refuses_rather_than_pretending(self, tmp_path: Path) -> None:
        assert main(["feeds", "sync", "--offline", "--cache-dir", str(tmp_path / "e")]) == 9

    def test_an_unknown_feed_is_refused(self, tmp_path: Path) -> None:
        assert (
            main(["feeds", "status", "--only", "nonsense", "--cache-dir", str(tmp_path / "e")])
            == 3
        )


class TestFeedsInCheck:
    def test_cached_feeds_are_used_without_opening_a_socket(
        self, scanned: Path, capsys: pytest.CaptureFixture
    ) -> None:
        assert (
            main(
                [
                    "check",
                    "--product",
                    str(scanned),
                    "CVE-2024-1086",
                    "--cache-dir",
                    str(FIXTURES / "feed-cache"),
                    "--json",
                ]
            )
            == 0
        )
        payload = json.loads(capsys.readouterr().out)
        assert payload["enrichment"]["actively_exploited"] is True
        assert "cisa-kev" in {e["source"] for e in payload["enrichment"]["evidence"]}

    def test_no_feeds_ignores_even_a_cached_copy(
        self, scanned: Path, capsys: pytest.CaptureFixture
    ) -> None:
        assert (
            main(
                [
                    "check",
                    "--product",
                    str(scanned),
                    "CVE-2024-1086",
                    "--cache-dir",
                    str(FIXTURES / "feed-cache"),
                    "--no-feeds",
                    "--json",
                ]
            )
            == 0
        )
        assert json.loads(capsys.readouterr().out)["enrichment"] == {}

    def test_feed_evidence_reaches_the_dossier(self, scanned: Path, tmp_path: Path) -> None:
        out = tmp_path / "dossier"
        main(
            [
                "report",
                "--product",
                str(scanned),
                "CVE-2024-1086",
                "--aware-at",
                AWARE,
                "--summary",
                "s",
                "--severity",
                "high",
                "--cache-dir",
                str(FIXTURES / "feed-cache"),
                "--out",
                str(out),
            ]
        )
        dossier = json.loads((out / "cve-2024-1086-early-warning.json").read_text())
        assert dossier["triage"]["enrichment"]["euvd_id"] == "EUVD-2024-1086"
        assert dossier["srp_fields"]["euvd_id"] in ("", "EUVD-2024-1086")

    def test_kev_makes_the_dossier_reportable_without_the_flag(
        self, scanned: Path, tmp_path: Path
    ) -> None:
        """The whole point of the feed layer: the hardest input, answered."""
        out = tmp_path / "dossier"
        main(
            [
                "report",
                "--product",
                str(scanned),
                "CVE-2024-1086",
                "--aware-at",
                AWARE,
                "--summary",
                "s",
                "--severity",
                "high",
                "--cache-dir",
                str(FIXTURES / "feed-cache"),
                "--out",
                str(out),
            ]
        )
        dossier = json.loads((out / "cve-2024-1086-early-warning.json").read_text())
        assert dossier["triage"]["reportable"] is True

    def test_an_explicit_no_overrides_the_feeds(
        self, scanned: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """A human decision is not overturned by a feed."""
        main(
            [
                "check",
                "--product",
                str(scanned),
                "CVE-2024-1086",
                "--cache-dir",
                str(FIXTURES / "feed-cache"),
                "--actively-exploited",
                "no",
                "--json",
            ]
        )
        assert json.loads(capsys.readouterr().out)["reportable"] is False


class TestWatchCommand:
    def test_once_runs_a_single_pass_and_exits_nonzero_on_a_reportable_finding(
        self, scanned: Path, tmp_path: Path
    ) -> None:
        products = tmp_path / "products"
        products.mkdir()
        (products / "p.json").write_text(scanned.read_text())
        code = main(
            [
                "watch",
                "--products",
                str(products),
                "--once",
                "--offline",
                "--cache-dir",
                str(FIXTURES / "feed-cache"),
                "--out",
                str(tmp_path / "d"),
                "--notify",
                f"file:{tmp_path / 'alerts.jsonl'}",
            ]
        )
        assert code == 1
        alerts = [
            json.loads(line) for line in (tmp_path / "alerts.jsonl").read_text().splitlines()
        ]
        assert any(a["reportable"] for a in alerts)
        assert all(a["dossier_path"] for a in alerts)

    def test_a_second_pass_sends_nothing(self, scanned: Path, tmp_path: Path) -> None:
        products = tmp_path / "products"
        products.mkdir()
        (products / "p.json").write_text(scanned.read_text())
        args = [
            "watch",
            "--products",
            str(products),
            "--once",
            "--offline",
            "--cache-dir",
            str(FIXTURES / "feed-cache"),
            "--out",
            str(tmp_path / "d"),
            "--notify",
            f"file:{tmp_path / 'alerts.jsonl'}",
        ]
        main(args)
        first = len((tmp_path / "alerts.jsonl").read_text().splitlines())
        main(args)
        assert len((tmp_path / "alerts.jsonl").read_text().splitlines()) == first

    def test_json_output_is_parseable(
        self, scanned: Path, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """--json means the stream is being parsed.

        The default stdout notifier printing after the JSON made the output
        unparseable — the kind of bug that surfaces in somebody's pipeline
        rather than in a terminal.
        """
        products = tmp_path / "products"
        products.mkdir()
        (products / "p.json").write_text(scanned.read_text())
        capsys.readouterr()  # discard whatever the scan fixture printed
        main(
            [
                "watch",
                "--products",
                str(products),
                "--once",
                "--offline",
                "--json",
                "--cache-dir",
                str(FIXTURES / "feed-cache"),
                "--out",
                str(tmp_path / "d"),
            ]
        )
        payload = json.loads(capsys.readouterr().out)
        assert payload["new_alerts"] > 0
        assert payload["alerts"][0]["cve"]

    def test_an_explicit_stdout_notifier_is_still_honoured_with_json(
        self, scanned: Path, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        products = tmp_path / "products"
        products.mkdir()
        (products / "p.json").write_text(scanned.read_text())
        main(
            [
                "watch",
                "--products",
                str(products),
                "--once",
                "--offline",
                "--json",
                "--notify",
                "stdout",
                "--cache-dir",
                str(FIXTURES / "feed-cache"),
                "--out",
                str(tmp_path / "d"),
            ]
        )
        assert "ACTION REQUIRED" in capsys.readouterr().out
