# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Version comparison for the versions embedded Linux actually ships.

Upstream advisories say "fixed in 1.2.4". A Yocto manifest says
``1.2.3+git0+abcdef1234-r0``. A Debian-derived rootfs says ``1:1.2.3-4ubuntu2.1``.
Comparing those with ``str`` or with a strict PEP 440 parser gets the wrong answer
quietly, and a wrong answer here is a CVE you did not report.

The algorithm is Debian's, which is the closest thing to a lingua franca across
OpenEmbedded, Buildroot and Debian-derived rootfs images. Yocto's ``PV`` sorting
follows it too; ``bitbake`` uses the same rules in ``vercmp``.

Reference for the ordering rules: Debian Policy Manual section 5.6.12.
"""

from __future__ import annotations

import re
from functools import total_ordering

# Yocto and Buildroot decorations that carry no ordering information.
#
# Order matters: the AUTOINC form must be tried before the bare ``+git`` form, or
# ``+gitAUTOINC+deadbeef`` loses only its ``+git`` and keeps the rest.
_NOISE = re.compile(
    r"""
      (\+gitAUTOINC\+[0-9a-f]+)       # +gitAUTOINC+abcdef1234
    | (\+git\d*\+[0-9a-f]{7,40})     # +git0+abcdef1234
    | (\+git\d*(?![0-9a-zA-Z]))       # a trailing +git or +git0
    | (\+svnAUTOINC\+r?\d+)
    | (\+svn\d*(?![0-9a-zA-Z]))
    | (\+hgAUTOINC\+[0-9a-f]+)
    | (-r\d+$)                        # Yocto PR
    """,
    re.VERBOSE,
)

_EPOCH = re.compile(r"^(\d+):(.*)$")


def normalise(version: str) -> str:
    """Strip build-system decoration that carries no ordering meaning."""
    v = (version or "").strip()
    while True:
        stripped = _NOISE.sub("", v)
        if stripped == v:
            return stripped
        v = stripped


def _split_epoch(version: str) -> tuple[int, str, str]:
    """Return ``(epoch, upstream_version, revision)``."""
    v = version
    epoch = 0
    m = _EPOCH.match(v)
    if m:
        epoch = int(m.group(1))
        v = m.group(2)
    if "-" in v:
        upstream, _, revision = v.rpartition("-")
    else:
        upstream, revision = v, ""
    return epoch, upstream, revision


def _order(char: str) -> int:
    """Debian's character ordering: ~ < (empty) < digits < letters < everything else."""
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    if char == "~":
        return -1
    return ord(char) + 256


def _compare_fragment(a: str, b: str) -> int:
    """Compare one upstream-version or revision fragment, Debian rules."""
    i = j = 0
    while i < len(a) or j < len(b):
        # Non-digit run.
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        # Digit run: strip leading zeros, longer run wins, else lexicographic.
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if first_diff == 0:
                first_diff = (a[i] > b[j]) - (a[i] < b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def compare(a: str, b: str) -> int:
    """Return -1, 0 or 1 for ``a`` against ``b``."""
    ea, ua, ra = _split_epoch(normalise(a))
    eb, ub, rb = _split_epoch(normalise(b))
    if ea != eb:
        return -1 if ea < eb else 1
    result = _compare_fragment(ua, ub)
    if result:
        return result
    return _compare_fragment(ra, rb)


@total_ordering
class Version:
    """A comparable, hashable wrapper. Keeps the original string for display."""

    __slots__ = ("_key", "raw")

    def __init__(self, raw: str) -> None:
        self.raw = raw or ""
        self._key = normalise(self.raw)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (Version, str)):
            return NotImplemented
        return compare(self.raw, other.raw if isinstance(other, Version) else other) == 0

    def __lt__(self, other: Version | str) -> bool:
        return compare(self.raw, other.raw if isinstance(other, Version) else other) < 0

    def __hash__(self) -> int:
        return hash(self._key)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"Version({self.raw!r})"

    def __str__(self) -> str:
        return self.raw


def in_range(
    version: str,
    *,
    introduced: str | None = None,
    fixed: str | None = None,
    last_affected: str | None = None,
) -> bool:
    """Is ``version`` inside a half-open advisory range?

    Follows the OSV convention: ``introduced`` is inclusive, ``fixed`` is
    exclusive, ``last_affected`` is inclusive. Passing neither bound means the
    range is unbounded and everything matches, which is what an advisory with no
    version data actually means.
    """
    if introduced and introduced != "0" and compare(version, introduced) < 0:
        return False
    if fixed and compare(version, fixed) >= 0:
        return False
    return not (last_affected and compare(version, last_affected) > 0)
