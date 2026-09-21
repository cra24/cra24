# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Ingesters. The tests that matter here are the ones about what does *not* ship."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cra24.errors import IngestError
from cra24.ingest import load_buildroot, load_sbom, load_yocto, read_kernel_config
from cra24.model import BuildStatus


class TestYocto:
    def test_reads_the_image_manifest(self, yocto_build: Path) -> None:
        p = load_yocto(yocto_build)
        assert p.find("busybox") is not None
        assert p.find("busybox").version == "1.36.1"
        assert p.find("busybox").arch == "aarch64"

    def test_a_recipe_built_but_not_installed_is_dropped(self, yocto_build: Path) -> None:
        """curl-native is in cve-check output and in no image. It does not ship."""
        assert load_yocto(yocto_build).find("curl-native") is None

    def test_include_unshipped_keeps_it(self, yocto_build: Path) -> None:
        p = load_yocto(yocto_build, include_unshipped=True)
        assert p.find("curl-native") is not None

    def test_a_recipe_whose_packages_ship_under_another_name_is_kept(
        self, yocto_build: Path
    ) -> None:
        """linux-raspberrypi ships as kernel-image-image.

        Dropping it because its own name is absent from the manifest is how a
        kernel CVE silently vanishes from a dossier. This is the regression that
        motivated the recipe -> package map.
        """
        kernel = load_yocto(yocto_build).find("linux-raspberrypi")
        assert kernel is not None
        assert "kernel-image-image" in kernel.provides
        assert "CVE-2024-1086" in kernel.unpatched_cves

    def test_cve_status_reason_strings_survive_ingest(self, yocto_build: Path) -> None:
        busybox = load_yocto(yocto_build).find("busybox")
        record = busybox.record("CVE-2023-42364")
        assert record.status is BuildStatus.IGNORED
        assert record.detail.startswith("not-applicable-config")
        assert "CONFIG_AWK" in record.detail

    def test_licences_are_attached(self, yocto_build: Path) -> None:
        assert "Apache-2.0" in load_yocto(yocto_build).find("openssl").licenses

    def test_kernel_config_is_found_automatically(self, yocto_build: Path) -> None:
        p = load_yocto(yocto_build)
        assert p.kernel_config["CONFIG_NF_TABLES"] == "m"
        assert p.kernel_config["CONFIG_KSMBD"] == "n"

    def test_a_non_build_directory_is_rejected_with_a_hint(self, tmp_path: Path) -> None:
        with pytest.raises(IngestError) as excinfo:
            load_yocto(tmp_path)
        assert "no tmp/" in str(excinfo.value)

    def test_a_missing_kernel_config_is_an_error_when_asked_for(
        self, yocto_build: Path
    ) -> None:
        with pytest.raises(IngestError):
            load_yocto(yocto_build, kernel_config="/nonexistent/.config")


class TestBuildroot:
    def test_reads_legal_info(self, buildroot_output: Path) -> None:
        p = load_buildroot(buildroot_output)
        assert p.find("openssl").version == "3.0.12"
        assert "Apache-2.0" in p.find("openssl").licenses

    def test_ignore_cves_becomes_an_ignored_record(self, buildroot_output: Path) -> None:
        record = load_buildroot(buildroot_output).find("busybox").record("CVE-2023-42364")
        assert record.status is BuildStatus.IGNORED
        assert "IGNORE_CVES" in record.detail

    def test_enabled_but_uninstalled_packages_are_not_claimed_to_ship(
        self, buildroot_output: Path
    ) -> None:
        """host-pkgconf is in pkg-stats and not in legal-info. It is a host tool."""
        assert load_buildroot(buildroot_output).find("host-pkgconf") is None

    def test_kernel_config_is_found(self, buildroot_output: Path) -> None:
        assert load_buildroot(buildroot_output).kernel_config["CONFIG_NF_TABLES"] == "m"


class TestSbom:
    def test_cyclonedx_components_and_metadata(self, fixtures: Path) -> None:
        p = load_sbom(fixtures / "sbom-cyclonedx.json")
        assert p.name == "AcmeGateway"
        assert p.version == "2.4.0"
        assert p.find("openssl").purl == "pkg:generic/openssl@3.0.12"
        assert p.find("openssl").cpes

    def test_cyclonedx_vex_analysis_is_preserved(self, fixtures: Path) -> None:
        """An SBOM that already carries triage decisions should not lose them."""
        p = load_sbom(fixtures / "sbom-cyclonedx.json")
        assert p.find("linux").record("CVE-2024-1086").status is BuildStatus.UNPATCHED
        busybox = p.find("busybox").record("CVE-2023-42364")
        assert busybox.status is BuildStatus.IGNORED
        assert "code_not_present" in busybox.detail

    def test_spdx(self, fixtures: Path) -> None:
        p = load_sbom(fixtures / "sbom-spdx.json")
        assert p.find("busybox").purl == "pkg:generic/busybox@1.36.1"
        assert p.find("busybox").cpes

    def test_junk_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "junk.json"
        path.write_text(json.dumps({"hello": "world"}))
        with pytest.raises(IngestError):
            load_sbom(path)

    def test_invalid_json_is_rejected_readably(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        with pytest.raises(IngestError) as excinfo:
            load_sbom(path)
        assert "not valid JSON" in str(excinfo.value)


class TestKernelConfig:
    def test_unset_is_recorded_as_n_not_omitted(self, tmp_path: Path) -> None:
        """'we looked and it is off' must stay distinguishable from 'we never looked'."""
        path = tmp_path / ".config"
        path.write_text('CONFIG_A=y\n# CONFIG_B is not set\nCONFIG_C=m\nCONFIG_D="quoted"\n')
        cfg = read_kernel_config(path)
        assert cfg == {"CONFIG_A": "y", "CONFIG_B": "n", "CONFIG_C": "m", "CONFIG_D": "quoted"}
        assert "CONFIG_NEVER_MENTIONED" not in cfg


class TestKernelConfigSymbolNames:
    """Kconfig symbols are conventionally upper case, but not exclusively.

    Every name below is real, taken from a stock Ubuntu 6.8 config. An
    upper-case-only pattern dropped 36 enabled symbols from that one file, and a
    dropped ``=m`` is worse than a parse error: the symbol becomes *absent*,
    absence in a complete config reads as "not enabled", and the gate then
    reports a driver that is compiled in and shipping as not affected — with an
    evidence string saying it is "not set in the shipped kernel config".
    """

    REAL_SYMBOLS = [
        ("CONFIG_SCSI_DC395x=m", "CONFIG_SCSI_DC395x", "m"),
        ("CONFIG_MT76x02_LIB=m", "CONFIG_MT76x02_LIB", "m"),
        ("CONFIG_MT792x_USB=m", "CONFIG_MT792x_USB", "m"),
        ("CONFIG_ARCNET_COM90xxIO=m", "CONFIG_ARCNET_COM90xxIO", "m"),
        ("CONFIG_MTD_NETtel=m", "CONFIG_MTD_NETtel", "m"),
        ("CONFIG_FONT_8x16=y", "CONFIG_FONT_8x16", "y"),
    ]

    @pytest.mark.parametrize(("line", "symbol", "value"), REAL_SYMBOLS)
    def test_a_symbol_with_lower_case_is_parsed(
        self, tmp_path: Path, line: str, symbol: str, value: str
    ) -> None:
        cfg = tmp_path / ".config"
        cfg.write_text(f"#\n# Automatically generated file; DO NOT EDIT.\n#\n{line}\n")
        assert read_kernel_config(cfg)[symbol] == value

    def test_an_unset_symbol_with_lower_case_is_recorded_as_n(self, tmp_path: Path) -> None:
        cfg = tmp_path / ".config"
        cfg.write_text(
            "#\n# Automatically generated file; DO NOT EDIT.\n#\n"
            "# CONFIG_FONT_6x11 is not set\n"
        )
        assert read_kernel_config(cfg)["CONFIG_FONT_6x11"] == "n"

    def test_a_compiled_in_driver_is_never_reported_as_gated_out(self, tmp_path: Path) -> None:
        """The failure this guards, end to end.

        CONFIG_MT76x02_LIB=m means the driver ships. The gate must say the
        product *is* affected, not invent an absence.
        """
        from cra24.model import Component, Product
        from cra24.triage import _config_gate

        cfg = tmp_path / ".config"
        cfg.write_text(
            "#\n# Automatically generated file; DO NOT EDIT.\n#\nCONFIG_MT76x02_LIB=m\n"
        )
        product = Product(name="Gateway", version="1.0")
        product.kernel_config = read_kernel_config(cfg)
        product.kernel_config_complete = True

        gated = _config_gate(
            product, Component(name="linux", version="6.8"), ["CONFIG_MT76x02_LIB"]
        )
        assert gated is not None
        assert gated[0] is False, "a driver compiled in as a module was gated out"
        assert "CONFIG_MT76x02_LIB=m" in gated[1]


class TestSbomKernelConfig:
    """``--kernel-config`` must work with ``--sbom``, not just with a build tree.

    An SBOM lists packages; a kernel CVE is answered by the configuration. The
    flag was offered alongside ``--sbom`` and silently ignored, so gating was
    quietly off on the one path where the user had explicitly asked for it.
    """

    def _sbom(self, tmp_path: Path) -> Path:
        doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"type": "library", "name": "linux", "version": "6.8.0"}],
        }
        p = tmp_path / "sbom.json"
        p.write_text(json.dumps(doc))
        return p

    def test_the_config_is_read_and_marked_complete(self, tmp_path: Path) -> None:
        cfg = tmp_path / ".config"
        cfg.write_text("#\n# Automatically generated file; DO NOT EDIT.\n#\nCONFIG_KSMBD=y\n")
        product = load_sbom(self._sbom(tmp_path), kernel_config=cfg)
        assert product.kernel_config["CONFIG_KSMBD"] == "y"
        assert product.kernel_config_complete is True

    def test_a_fragment_is_read_but_not_marked_complete(self, tmp_path: Path) -> None:
        cfg = tmp_path / "frag.cfg"
        cfg.write_text("CONFIG_KSMBD=y\n")
        product = load_sbom(self._sbom(tmp_path), kernel_config=cfg)
        assert product.kernel_config_complete is False

    def test_a_missing_config_is_an_error_rather_than_silence(self, tmp_path: Path) -> None:
        with pytest.raises(IngestError):
            load_sbom(self._sbom(tmp_path), kernel_config="/nonexistent/.config")

    def test_without_the_flag_nothing_changes(self, tmp_path: Path) -> None:
        product = load_sbom(self._sbom(tmp_path))
        assert product.kernel_config == {}
        assert product.kernel_config_complete is False
