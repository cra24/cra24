# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Shared fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cra24 import config as config_mod
from cra24.feeds import Cache, FeedSet
from cra24.ingest import load_sbom, load_yocto
from cra24.model import BuildStatus, Component, Manufacturer, Product

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def yocto_build() -> Path:
    return FIXTURES / "yocto-build"


@pytest.fixture
def buildroot_output() -> Path:
    return FIXTURES / "buildroot-output"


@pytest.fixture
def demo_config() -> dict:
    return json.loads((FIXTURES / "demo-config.json").read_text())


@pytest.fixture
def product(yocto_build: Path, demo_config: dict) -> Product:
    p = load_yocto(yocto_build)
    return config_mod.apply(p, demo_config)


@pytest.fixture
def cdx_product() -> Product:
    return load_sbom(FIXTURES / "sbom-cyclonedx.json")


@pytest.fixture
def minimal_product() -> Product:
    """A hand-built product, for tests that should not depend on a fixture tree."""
    comp = Component(
        name="libfoo", version="1.2.3", purl="pkg:generic/libfoo@1.2.3", origin="test"
    )
    comp.add_cve("CVE-2026-0001", BuildStatus.UNPATCHED, source="test")
    return Product(
        name="TestDevice",
        version="1.0.0",
        manufacturer=Manufacturer(
            name="Test SAS",
            country="FR",
            coordinator_csirt="CERT-FR",
            contact_email="psirt@test.invalid",
            csaf_namespace="https://test.invalid",
        ),
        components=[comp],
        member_states=["FR"],
        annex_class="important-i",
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "schema: requires jsonschema")


@pytest.fixture
def feed_cache(tmp_path: Path) -> Cache:
    """A copy of the recorded feed fixtures, so a test can write to it freely."""
    import shutil

    dest = tmp_path / "feed-cache"
    shutil.copytree(FIXTURES / "feed-cache", dest)
    return Cache(dest)


@pytest.fixture
def offline_feeds(feed_cache: Cache) -> FeedSet:
    """Every feed, offline, backed by the recorded fixtures.

    Tests never touch the network. A test suite that depends on CISA being up is
    one that fails for reasons that have nothing to do with the code.
    """
    return FeedSet(cache=feed_cache, offline=True)
