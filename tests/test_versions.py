# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Version comparison. Getting this wrong means missing a CVE, so it is tested hard."""

from __future__ import annotations

import pytest

from cra24.versions import Version, compare, in_range, normalise


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.2.3", "1.2.4", -1),
        ("1.2.4", "1.2.3", 1),
        ("1.2.3", "1.2.3", 0),
        ("1.10", "1.9", 1),  # not string ordering
        ("1.0", "1.0.1", -1),
        ("0.9", "1.0", -1),
        ("5.15.0", "5.9.0", 1),
        ("1.0.0", "1.0.0a", -1),
        ("2.36-9+deb12u7", "2.36-9", 1),
        ("1:1.0", "2.0", 1),  # epoch wins
        ("1.0~rc1", "1.0", -1),  # tilde sorts before
        ("1.0~rc1", "1.0~rc2", -1),
        ("1.0", "1.0~rc1", 1),
        ("01.2", "1.2", 0),  # leading zeros are noise
    ],
)
def test_compare(a: str, b: str, expected: int) -> None:
    assert compare(a, b) == expected
    assert compare(b, a) == -expected


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("1.2.3+git0+abcdef1234-r0", "1.2.3"),
        ("1.2.3+gitAUTOINC+deadbeef", "1.2.3"),
        ("6.6.22-r0", "6.6.22"),
        ("1.36.1", "1.36.1"),
    ],
)
def test_normalise_strips_build_noise(raw: str, clean: str) -> None:
    assert normalise(raw) == clean


def test_yocto_decoration_does_not_change_ordering() -> None:
    assert compare("1.2.3+git0+abcdef1234-r0", "1.2.3") == 0
    assert compare("1.2.3+git0+abcdef1234-r0", "1.2.4") == -1


def test_version_object_sorts_and_hashes() -> None:
    versions = [Version("1.10"), Version("1.9"), Version("1.2.3")]
    assert [str(v) for v in sorted(versions)] == ["1.2.3", "1.9", "1.10"]
    assert Version("1.2.3+git0-r0") == Version("1.2.3")
    assert len({Version("1.2.3"), Version("1.2.3+git0-r0")}) == 1


@pytest.mark.parametrize(
    ("version", "kwargs", "expected"),
    [
        ("5.10.1", {"fixed": "5.10.5"}, True),
        ("5.10.5", {"fixed": "5.10.5"}, False),  # fixed is exclusive
        ("5.10.9", {"fixed": "5.10.5"}, False),
        ("4.9", {"introduced": "5.0"}, False),
        ("5.0", {"introduced": "5.0"}, True),  # introduced is inclusive
        ("5.4", {"introduced": "5.0", "fixed": "5.10"}, True),
        ("5.4", {"last_affected": "5.4"}, True),  # last_affected is inclusive
        ("5.5", {"last_affected": "5.4"}, False),
        ("anything", {}, True),  # unbounded range matches all
        ("1.0", {"introduced": "0"}, True),  # OSV's "0" means from the start
    ],
)
def test_in_range(version: str, kwargs: dict, expected: bool) -> None:
    assert in_range(version, **kwargs) is expected


def test_empty_versions_do_not_explode() -> None:
    assert compare("", "") == 0
    assert compare("", "1.0") == -1
