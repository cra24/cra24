# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""The triage engine.

These tests encode the safety properties, not just the happy path. The ones that
matter most are the asymmetries: what the engine is allowed to conclude from
absent evidence, and what it must refuse to conclude.
"""

from __future__ import annotations

import pytest

from cra24.model import BuildStatus, Component, Product
from cra24.triage import (
    REASON_MAP,
    Confidence,
    Justification,
    VexStatus,
    _config_gate,
    triage,
    triage_component,
)


def _product(**kwargs) -> Product:
    return Product(name="Device", version="1.0", **kwargs)


class TestPresence:
    def test_absent_cve_is_not_affected_and_not_reportable(self, product: Product) -> None:
        result = triage(product, "CVE-9999-99999")
        assert result.status is VexStatus.NOT_AFFECTED
        assert result.reportable is False
        assert "do not report" in result.summary

    def test_unpatched_component_is_affected(self, product: Product) -> None:
        assert triage(product, "CVE-2024-1086").status is VexStatus.AFFECTED


class TestArticle14Trigger:
    """Article 14(1) turns on active exploitation, not on severity."""

    def test_affected_and_actively_exploited_is_reportable(self, product: Product) -> None:
        result = triage(product, "CVE-2024-1086", actively_exploited=True)
        assert result.reportable is True
        assert "24-hour clock" in result.reportable_reason

    def test_affected_without_exploitation_is_not_reportable(self, product: Product) -> None:
        result = triage(product, "CVE-2024-1086", actively_exploited=False)
        assert result.reportable is False
        assert "Annex I Part II" in result.reportable_reason

    def test_unknown_exploitation_refuses_to_guess(self, product: Product) -> None:
        result = triage(product, "CVE-2024-1086", actively_exploited=None)
        assert result.reportable is False
        assert "establish that before filing" in result.reportable_reason


class TestBuildMetadata:
    def test_cve_status_reason_maps_to_a_vex_justification(self, product: Product) -> None:
        result = triage(product, "CVE-2023-42364")
        comp = result.components[0]
        assert comp.status is VexStatus.NOT_AFFECTED
        assert comp.justification is Justification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH

    def test_fixed_version_reason_yields_fixed(self, product: Product) -> None:
        assert triage(product, "CVE-2024-0727").status is VexStatus.FIXED

    def test_disputed_is_under_investigation_not_a_verdict(self, product: Product) -> None:
        result = triage(product, "CVE-2024-2511")
        assert result.status is VexStatus.UNDER_INVESTIGATION
        assert result.requires_human is True

    def test_patched_without_a_reason_demands_a_human(self) -> None:
        """A layer applying a patch is evidence, not proof."""
        comp = Component(name="x", version="1.0", origin="test")
        comp.add_cve("CVE-2026-1", BuildStatus.PATCHED, source="test")  # no detail
        result = triage(_product(components=[comp]), "CVE-2026-1")
        assert result.status is VexStatus.FIXED
        assert result.requires_human is True
        assert result.components[0].confidence is Confidence.LOW

    def test_ignored_without_a_reason_yields_an_impact_statement(self) -> None:
        """A published not_affected needs something a reader can check."""
        comp = Component(name="x", version="1.0", origin="test")
        comp.add_cve("CVE-2026-2", BuildStatus.IGNORED, source="test")
        result = triage(_product(components=[comp]), "CVE-2026-2")
        assert result.components[0].justification is None
        assert result.components[0].impact_statement


class TestKernelConfigGating:
    def test_an_unset_symbol_downgrades_affected_to_not_affected(
        self, product: Product
    ) -> None:
        result = triage(product, "CVE-2024-1086", gate_symbols=["CONFIG_KSMBD"])
        comp = result.components[0]
        assert comp.status is VexStatus.NOT_AFFECTED
        assert comp.justification is Justification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
        assert comp.confidence is Confidence.HIGH

    def test_an_enabled_symbol_leaves_affected_alone(self, product: Product) -> None:
        result = triage(product, "CVE-2024-1086", gate_symbols=["CONFIG_NF_TABLES"])
        assert result.components[0].status is VexStatus.AFFECTED

    def test_gating_never_upgrades_a_negative_verdict(self, product: Product) -> None:
        """An enabled symbol must not turn not_affected into affected."""
        result = triage(product, "CVE-2023-42364", gate_symbols=["CONFIG_NF_TABLES"])
        assert result.components[0].status is VexStatus.NOT_AFFECTED

    def test_no_kernel_config_means_no_conclusion(self) -> None:
        """Absence of gating data is never read as 'not gated'."""
        comp = Component(name="linux", version="6.6", origin="test")
        comp.add_cve("CVE-2026-3", BuildStatus.UNPATCHED, source="test")
        product = _product(components=[comp])  # no kernel_config at all
        result = triage(product, "CVE-2026-3", gate_symbols=["CONFIG_ANYTHING"])
        assert result.components[0].status is VexStatus.AFFECTED
        assert not any(f.rule == "kernel-config-gate" for f in result.components[0].findings)


class TestAdvisoryVersionRange:
    def test_a_version_past_the_fix_is_fixed(self) -> None:
        comp = Component(name="openssl", version="3.0.14", origin="test")
        comp.add_cve("CVE-2026-4", BuildStatus.UNPATCHED, source="test")
        result = triage(
            _product(components=[comp]), "CVE-2026-4", advisory_fixed_version="3.0.13"
        )
        assert result.status is VexStatus.FIXED

    def test_a_version_before_the_introduction_is_not_affected(self) -> None:
        comp = Component(name="linux", version="4.19", origin="test")
        comp.add_cve("CVE-2026-5", BuildStatus.UNPATCHED, source="test")
        result = triage(
            _product(components=[comp]),
            "CVE-2026-5",
            advisory_introduced="5.0",
            advisory_fixed_version="6.1",
        )
        assert result.status is VexStatus.NOT_AFFECTED
        assert result.components[0].justification is Justification.VULNERABLE_CODE_NOT_PRESENT

    def test_a_version_inside_the_range_stays_affected(self) -> None:
        comp = Component(name="linux", version="5.10", origin="test")
        comp.add_cve("CVE-2026-6", BuildStatus.UNPATCHED, source="test")
        result = triage(
            _product(components=[comp]),
            "CVE-2026-6",
            advisory_introduced="5.0",
            advisory_fixed_version="6.1",
        )
        assert result.status is VexStatus.AFFECTED


class TestEvidence:
    def test_every_verdict_records_the_rules_that_fired(self, product: Product) -> None:
        for comp in triage(product, "CVE-2023-42364").components:
            assert comp.findings
            assert all(f.rule and f.conclusion for f in comp.findings)

    def test_findings_carry_their_source_file(self, product: Product) -> None:
        comp = triage(product, "CVE-2024-1086").components[0]
        assert any("cve-summary" in f.source for f in comp.findings)

    def test_affected_components_get_an_action_statement(self, product: Product) -> None:
        comp = triage(product, "CVE-2024-1086").components[0]
        assert comp.action_statement


class TestAggregation:
    def test_the_worst_component_status_wins(self) -> None:
        good = Component(name="a", version="1", origin="test")
        good.add_cve("CVE-2026-7", BuildStatus.PATCHED, detail="fixed-version", source="t")
        bad = Component(name="b", version="1", origin="test")
        bad.add_cve("CVE-2026-7", BuildStatus.UNPATCHED, source="t")
        assert (
            triage(_product(components=[good, bad]), "CVE-2026-7").status is VexStatus.AFFECTED
        )


class TestReasonVocabulary:
    @pytest.mark.parametrize("reason", sorted(REASON_MAP))
    def test_every_justification_is_from_the_closed_openvex_vocabulary(
        self, reason: str
    ) -> None:
        status, justification, _ = REASON_MAP[reason]
        if justification is not None:
            assert isinstance(justification, Justification)
            assert status is VexStatus.NOT_AFFECTED, (
                "a justification is only valid alongside not_affected"
            )

    def test_cyclonedx_justifications_are_understood(self, cdx_product: Product) -> None:
        comp = triage(cdx_product, "CVE-2023-42364").components[0]
        assert comp.justification is Justification.VULNERABLE_CODE_NOT_PRESENT


def test_triage_component_is_usable_standalone(product: Product) -> None:
    comp = product.find("busybox")
    result = triage_component(product, comp, "CVE-2023-42364")
    assert result.component == "busybox"


class TestConfigGateCompleteness:
    """What an *absent* kernel symbol is allowed to mean.

    ``read_kernel_config`` records an explicitly unset symbol as ``"n"`` so that
    "we looked and it is off" stays distinguishable from "we never looked". The
    gate used to collapse the two, which let a config fragment that never
    mentioned a symbol gate a live vulnerability out of the dossier.
    """

    def _product(self, config: dict[str, str], *, complete: bool) -> Product:
        p = Product(name="Gateway", version="1.0")
        p.kernel_config = config
        p.kernel_config_complete = complete
        return p

    @pytest.fixture
    def component(self) -> Component:
        return Component(name="linux", version="6.6.22")

    def test_a_generated_config_may_conclude_from_absence(self, component: Component) -> None:
        """kconfig considered every reachable symbol, so absence is an answer."""
        product = self._product({"CONFIG_FOO": "y"}, complete=True)
        gated, evidence = _config_gate(product, component, ["CONFIG_KSMBD"])
        assert gated is True
        assert "CONFIG_KSMBD" in evidence

    def test_a_fragment_must_not_conclude_from_absence(self, component: Component) -> None:
        """The regression that mattered: this must refuse to answer."""
        product = self._product({"CONFIG_FOO": "y"}, complete=False)
        assert _config_gate(product, component, ["CONFIG_KSMBD"]) is None

    def test_an_explicit_n_still_concludes_in_a_fragment(self, component: Component) -> None:
        """ "# CONFIG_X is not set" is evidence wherever it appears."""
        product = self._product({"CONFIG_KSMBD": "n"}, complete=False)
        gated, _ = _config_gate(product, component, ["CONFIG_KSMBD"])
        assert gated is True

    def test_an_enabled_symbol_always_wins(self, component: Component) -> None:
        for complete in (True, False):
            product = self._product({"CONFIG_KSMBD": "y"}, complete=complete)
            gated, evidence = _config_gate(product, component, ["CONFIG_KSMBD"])
            assert gated is False
            assert "CONFIG_KSMBD=y" in evidence

    def test_one_unknown_symbol_poisons_an_otherwise_disabled_set(
        self, component: Component
    ) -> None:
        """A symbol we never saw could be the one that enables the code."""
        product = self._product({"CONFIG_A": "n"}, complete=False)
        assert _config_gate(product, component, ["CONFIG_A", "CONFIG_B"]) is None
