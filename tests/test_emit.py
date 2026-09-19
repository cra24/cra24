# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Emitters, validated against the real schemas.

The point of these tests is the schema assertions. An advisory that does not
validate is one a customer's tooling silently drops, which is worse than not
publishing: you believe you informed them and you did not.
"""

from __future__ import annotations

import pytest

from cra24.clock import Track
from cra24.emit import csaf as csaf_mod
from cra24.emit import srp as srp_mod
from cra24.emit import validate as validate_mod
from cra24.emit import vex as vex_mod
from cra24.errors import ValidationError
from cra24.model import Product
from cra24.triage import triage

schema = pytest.mark.skipif(not validate_mod.available(), reason="jsonschema not installed")

AWARE = "2026-09-17T08:30:00Z"


@pytest.fixture
def affected(product: Product):
    return triage(product, "CVE-2024-1086", actively_exploited=True)


@pytest.fixture
def not_affected(product: Product):
    return triage(product, "CVE-2023-42364")


@pytest.fixture
def absent(product: Product):
    return triage(product, "CVE-9999-99999")


class TestCsaf:
    @schema
    @pytest.mark.parametrize("case", ["affected", "not_affected", "absent"])
    def test_every_advisory_validates(
        self, product: Product, case: str, request: pytest.FixtureRequest
    ) -> None:
        result = request.getfixturevalue(case)
        doc = csaf_mod.build(product, result, "TEST-1")
        assert validate_mod.validate_csaf(doc, strict=False) == []

    def test_it_is_a_vex_profile_document(self, product: Product, affected) -> None:
        doc = csaf_mod.build(product, affected, "TEST-1")
        assert doc["document"]["category"] == "csaf_vex"
        assert doc["document"]["csaf_version"] == "2.0"

    def test_the_component_is_modelled_inside_the_product(
        self, product: Product, affected
    ) -> None:
        """A bare 'product X is affected' answers none of an integrator's findings."""
        tree = csaf_mod.build(product, affected, "TEST-1")["product_tree"]
        rel = tree["relationships"][0]
        assert rel["category"] == "default_component_of"
        assert rel["relates_to_product_reference"] == csaf_mod.PRODUCT_ID

    def test_product_status_points_at_the_relationship_product(
        self, product: Product, affected
    ) -> None:
        doc = csaf_mod.build(product, affected, "TEST-1")
        rel_id = doc["product_tree"]["relationships"][0]["full_product_name"]["product_id"]
        assert doc["vulnerabilities"][0]["product_status"]["known_affected"] == [rel_id]

    def test_purls_reach_the_identification_helper(self, product: Product, affected) -> None:
        """Without one, matching falls back to string comparison and fails silently."""
        tree = csaf_mod.build(product, affected, "TEST-1")["product_tree"]
        component_branch = tree["branches"][1]["branches"][0]["product"]
        assert component_branch["product_identification_helper"]["purl"].startswith("pkg:")

    def test_every_known_not_affected_product_carries_a_justification(
        self, product: Product, not_affected
    ) -> None:
        doc = csaf_mod.build(product, not_affected, "TEST-1")
        vuln = doc["vulnerabilities"][0]
        negatives = set(vuln["product_status"].get("known_not_affected", []))
        justified = {pid for f in vuln.get("flags", []) for pid in f["product_ids"]}
        justified |= {pid for t in vuln.get("threats", []) for pid in t["product_ids"]}
        assert negatives <= justified

    def test_affected_products_carry_a_remediation(self, product: Product, affected) -> None:
        vuln = csaf_mod.build(product, affected, "TEST-1")["vulnerabilities"][0]
        assert vuln["remediations"]

    def test_the_disclaimer_is_not_removable_by_accident(
        self, product: Product, affected
    ) -> None:
        notes = csaf_mod.build(product, affected, "TEST-1")["document"]["notes"]
        assert any(n["category"] == "legal_disclaimer" for n in notes)

    def test_tracking_id_is_stable_and_readable(self, product: Product) -> None:
        tid = csaf_mod.tracking_id(product, "CVE-2024-1086")
        assert tid == csaf_mod.tracking_id(product, "CVE-2024-1086")
        assert "CVE-2024-1086" in tid

    @schema
    def test_an_invalid_document_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_mod.validate_csaf({"document": {"category": "csaf_vex"}})


class TestOpenVex:
    @schema
    @pytest.mark.parametrize("case", ["affected", "not_affected", "absent"])
    def test_every_document_validates(
        self, product: Product, case: str, request: pytest.FixtureRequest
    ) -> None:
        result = request.getfixturevalue(case)
        doc = vex_mod.build(product, result, "https://test.invalid/vex/1")
        assert validate_mod.validate_openvex(doc, strict=False) == []

    def test_the_context_is_the_exact_version_iri(self, product: Product, affected) -> None:
        doc = vex_mod.build(product, affected, "https://test.invalid/vex/1")
        assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"

    def test_not_affected_always_carries_a_justification_or_impact_statement(
        self, product: Product, not_affected
    ) -> None:
        """The commonest way an OpenVEX document turns out invalid."""
        doc = vex_mod.build(product, not_affected, "https://test.invalid/vex/1")
        for statement in doc["statements"]:
            if statement["status"] == "not_affected":
                assert "justification" in statement or "impact_statement" in statement

    def test_affected_carries_an_action_statement_and_its_timestamp(
        self, product: Product, affected
    ) -> None:
        doc = vex_mod.build(product, affected, "https://test.invalid/vex/1")
        statement = doc["statements"][0]
        assert statement["action_statement"]
        assert statement["action_statement_timestamp"]

    def test_the_component_appears_as_a_subcomponent_of_the_product(
        self, product: Product, affected
    ) -> None:
        doc = vex_mod.build(product, affected, "https://test.invalid/vex/1")
        entry = doc["statements"][0]["products"][0]
        assert entry["subcomponents"][0]["@id"].startswith("pkg:")

    def test_version_is_an_integer_that_the_caller_can_increment(
        self, product: Product, affected
    ) -> None:
        doc = vex_mod.build(product, affected, "https://test.invalid/vex/1", version=3)
        assert doc["version"] == 3

    def test_document_id_lands_in_the_manufacturer_namespace(self, product: Product) -> None:
        assert vex_mod.document_id(product, "CVE-2024-1086").startswith(
            product.manufacturer.csaf_namespace
        )


class TestSrpDossier:
    def test_a_complete_product_has_no_blocking_gaps(self, product: Product, affected) -> None:
        dossier = srp_mod.build(
            product, affected, AWARE, answers={"summary": "s", "severity": "high"}
        )
        assert dossier.ready, dossier.gaps

    def test_missing_identity_becomes_a_named_blocking_gap(self, affected) -> None:
        bare = Product(name="X", components=[])
        dossier = srp_mod.build(bare, affected, AWARE)
        keys = {g.split(" — ")[0] for g in dossier.gaps}
        assert {"manufacturer_name", "product_version", "affected_member_states"} <= keys

    def test_malicious_intent_is_mandatory_on_the_incident_track_only(
        self, product: Product, affected
    ) -> None:
        vuln = srp_mod.build(
            product, affected, AWARE, track=Track.VULNERABILITY, answers={"summary": "s"}
        )
        incident = srp_mod.build(
            product, affected, AWARE, track=Track.INCIDENT, answers={"summary": "s"}
        )
        assert not any("malicious_intent" in g for g in vuln.gaps)
        assert any("malicious_intent" in g for g in incident.gaps)

    def test_the_condition_grammar_is_not_eval(self) -> None:
        """The field spec is data a user can edit. Data never gets executed."""
        assert srp_mod._condition_holds("x == 'y'", {"x": "y"}) is True
        assert srp_mod._condition_holds("__import__('os').system('true')", {}) is False

    def test_later_stages_inherit_earlier_fields(self, product: Product, affected) -> None:
        dossier = srp_mod.build(
            product, affected, AWARE, stage="notification", answers={"summary": "s"}
        )
        assert "manufacturer_name" in dossier.fields
        assert "corrective_measures" in dossier.fields

    def test_the_markdown_leads_with_the_gaps(self, affected) -> None:
        bare = Product(name="X", components=[])
        text = srp_mod.to_markdown(srp_mod.build(bare, affected, AWARE))
        assert text.index("## Blocking") < text.index("## Clocks")

    def test_the_markdown_shows_only_the_relevant_legal_basis(
        self, product: Product, affected
    ) -> None:
        text = srp_mod.to_markdown(srp_mod.build(product, affected, AWARE))
        assert "Article 14(1)(a)" in text
        assert "Article 14(3)(a)" not in text

    def test_the_markdown_carries_the_unofficial_disclaimer(
        self, product: Product, affected
    ) -> None:
        text = srp_mod.to_markdown(srp_mod.build(product, affected, AWARE))
        assert "not affiliated" in text.lower()

    def test_the_evidence_trail_reaches_the_markdown(
        self, product: Product, not_affected
    ) -> None:
        text = srp_mod.to_markdown(srp_mod.build(product, not_affected, AWARE))
        assert "build-cve-status" in text


class TestValidationAvailability:
    """The preflight must agree with what an emit will actually do.

    Ubuntu ships jsonschema 4.10 in ``dist-packages`` with no ``referencing``.
    That combination used to report the validator as present and then die with a
    bare ``ModuleNotFoundError`` on the first emit — a green ``doctor`` followed
    by a crash mid-incident.
    """

    def _hide(self, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
        """Make ``import name`` fail, as it would on a machine without it."""
        import builtins

        real = builtins.__import__

        def fake(module: str, *args, **kwargs):
            if module == name or module.startswith(f"{name}."):
                raise ImportError(f"No module named {name!r}")
            return real(module, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake)

    @pytest.mark.parametrize("missing", ["jsonschema", "referencing"])
    def test_either_missing_dependency_is_named(
        self, monkeypatch: pytest.MonkeyPatch, missing: str
    ) -> None:
        self._hide(monkeypatch, missing)
        assert validate_mod.unavailable_reason() == f"{missing} is not installed"
        assert not validate_mod.available()

    def test_a_missing_dependency_raises_validation_error_not_import_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The whole point: a diagnosable error, not a traceback from an import."""
        self._hide(monkeypatch, "referencing")
        with pytest.raises(ValidationError) as exc:
            validate_mod.validate_openvex({"not": "a vex document"})
        assert "referencing is not installed" in str(exc.value)

    def test_a_jsonschema_too_old_for_the_registry_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """4.18 is where ``registry=`` arrived; older copies raise TypeError."""
        import importlib.metadata

        monkeypatch.setattr(importlib.metadata, "version", lambda _: "4.10.3")
        reason = validate_mod.unavailable_reason()
        assert "too old" in reason and "4.10.3" in reason

    @schema
    def test_a_healthy_install_reports_no_reason(self) -> None:
        assert validate_mod.unavailable_reason() == ""
        assert validate_mod.available()
