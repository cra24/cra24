# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""The canonical model, its validation, and backwards compatibility."""

from __future__ import annotations

from pathlib import Path

import pytest

from cra24.errors import ConfigError
from cra24.model import BuildStatus, Component, CveRecord, Manufacturer, Product


class TestComponent:
    def test_cve_ids_are_normalised_to_upper_case(self) -> None:
        comp = Component(name="x", version="1")
        comp.add_cve("cve-2026-1", BuildStatus.PATCHED)
        assert comp.record("CVE-2026-1") is not None
        assert comp.record("cve-2026-1") is not None
        assert comp.patched_cves == ["CVE-2026-1"]

    def test_a_concrete_status_replaces_an_unknown_one(self) -> None:
        comp = Component(name="x", version="1")
        comp.add_cve("CVE-2026-1", BuildStatus.UNKNOWN, source="a")
        comp.add_cve("CVE-2026-1", BuildStatus.UNPATCHED, source="b")
        assert comp.status("CVE-2026-1") is BuildStatus.UNPATCHED

    def test_a_concrete_status_is_not_overwritten_by_a_later_source(self) -> None:
        """Two scanners disagreeing must not silently become last-write-wins."""
        comp = Component(name="x", version="1")
        comp.add_cve("CVE-2026-1", BuildStatus.PATCHED, source="a")
        comp.add_cve("CVE-2026-1", BuildStatus.UNPATCHED, source="b")
        assert comp.status("CVE-2026-1") is BuildStatus.PATCHED

    def test_an_empty_cve_id_is_refused(self) -> None:
        with pytest.raises(ConfigError):
            Component(name="x", version="1").add_cve("", BuildStatus.UNPATCHED)

    def test_identifier_falls_back_to_a_generic_purl(self) -> None:
        assert Component(name="x", version="1").identifier() == "pkg:generic/x@1"


class TestProductValidation:
    def test_a_complete_product_validates(self, product: Product) -> None:
        assert product.validate() == []

    def test_missing_version_is_reported_with_the_reason(self) -> None:
        gaps = Product(name="X", components=[Component(name="c")]).validate()
        assert any("version" in g and "own field" in g for g in gaps)

    def test_member_states_are_checked_against_the_eu_list(self) -> None:
        p = Product(
            name="X",
            version="1",
            member_states=["FR", "US", "GB"],
            components=[Component(name="c")],
        )
        gaps = p.validate()
        assert any("GB" in g and "US" in g for g in gaps)

    def test_a_non_eu_manufacturer_country_is_flagged_helpfully(self) -> None:
        man = Manufacturer(
            name="N", country="US", coordinator_csirt="X", contact_email="a@b.invalid"
        )
        gaps = man.validate()
        assert any("authorised representative" in g for g in gaps)

    def test_an_empty_inventory_is_a_gap(self) -> None:
        assert any("components" in g for g in Product(name="X", version="1").validate())


class TestSerialisation:
    def test_round_trip_preserves_everything(self, product: Product) -> None:
        restored = Product.from_dict(product.to_dict())
        assert restored.counts() == product.counts()
        assert restored.manufacturer == product.manufacturer
        assert restored.kernel_config == product.kernel_config

    def test_cve_provenance_survives_the_round_trip(self, product: Product) -> None:
        """The justification is the part every other tool throws away."""
        original = product.find("busybox").record("CVE-2023-42364")
        restored = Product.from_dict(product.to_dict()).find("busybox")
        assert restored.record("CVE-2023-42364").detail == original.detail
        assert restored.record("CVE-2023-42364").source == original.source

    def test_saving_is_deterministic(self, product: Product, tmp_path: Path) -> None:
        a = product.save(tmp_path / "a.json").read_text()
        b = product.save(tmp_path / "b.json").read_text()
        assert a == b

    def test_the_0_1_flat_format_still_loads(self) -> None:
        legacy = {
            "name": "old",
            "version": "1",
            "components": [
                {
                    "name": "zlib",
                    "version": "1.2.13",
                    "patched_cves": ["CVE-2022-37434"],
                    "unpatched_cves": [],
                    "ignored_cves": [],
                }
            ],
        }
        product = Product.from_dict(legacy)
        assert product.find("zlib").patched_cves == ["CVE-2022-37434"]

    def test_an_unknown_key_is_an_error_not_a_silent_drop(self) -> None:
        with pytest.raises(ConfigError) as excinfo:
            Product.from_dict({"name": "x", "typoed_key": 1})
        assert "typoed_key" in str(excinfo.value)

    def test_a_missing_file_gives_an_actionable_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError) as excinfo:
            Product.load(tmp_path / "nope.json")
        assert "cra24 scan" in str(excinfo.value)

    def test_invalid_json_names_the_file(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{")
        with pytest.raises(ConfigError) as excinfo:
            Product.load(path)
        assert "not valid JSON" in str(excinfo.value)


class TestLookups:
    def test_bearing_returns_components_with_their_records(self, product: Product) -> None:
        bearing = product.bearing("CVE-2024-1086")
        assert [c.name for c, _ in bearing] == ["linux-raspberrypi"]
        assert all(isinstance(r, CveRecord) for _, r in bearing)

    def test_bearing_is_case_insensitive(self, product: Product) -> None:
        assert product.bearing("cve-2024-1086") == product.bearing("CVE-2024-1086")

    def test_counts_add_up(self, product: Product) -> None:
        counts = product.counts()
        total = sum(len(c.cves) for c in product.components)
        assert (
            counts["patched"] + counts["unpatched"] + counts["ignored"] + counts["unknown"]
            == total
        )
