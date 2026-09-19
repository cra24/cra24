# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Shared helpers for ingesters."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..model import Product

#: ``CONFIG_FOO=y`` / ``CONFIG_FOO=m`` / ``# CONFIG_FOO is not set``
_CONFIG_SET = re.compile(r"^(CONFIG_[A-Z0-9_]+)=(.*)$")
_CONFIG_UNSET = re.compile(r"^# (CONFIG_[A-Z0-9_]+) is not set$")

#: The banner kconfig writes at the top of every ``.config`` it generates.
#: A defconfig, a ``*.cfg`` fragment or a hand-written snippet does not carry it.
_GENERATED_BANNER = re.compile(r"^#\s*Automatically generated file", re.MULTILINE)


def is_generated_config(path: str | Path) -> bool:
    """Did kconfig write this file, or did a human?

    The difference decides what an *absent* symbol is allowed to mean. In a
    generated ``.config`` every symbol the build could reach was considered, so
    a symbol that does not appear was not enabled. In a defconfig or a fragment
    only the deltas are listed, and absence means nothing at all.

    Reading absence as "disabled" in the second case is how a vulnerable
    subsystem gets gated out of a dossier on the strength of a file that never
    mentioned it.
    """
    try:
        head = Path(path).read_text(errors="replace")[:4096]
    except OSError:
        return False
    return bool(_GENERATED_BANNER.search(head))


def read_kernel_config(path: str | Path) -> dict[str, str]:
    """Parse a Linux ``.config``.

    Explicitly unset symbols are recorded as ``"n"`` rather than omitted, because
    "we looked and it is off" and "we never looked" must stay distinguishable.
    Triage depends on that distinction and gets it wrong in the dangerous
    direction if the two collapse.
    """
    out: dict[str, str] = {}
    for line in Path(path).read_text(errors="replace").splitlines():
        line = line.strip()
        m = _CONFIG_SET.match(line)
        if m:
            out[m.group(1)] = m.group(2).strip().strip('"')
            continue
        m = _CONFIG_UNSET.match(line)
        if m:
            out[m.group(1)] = "n"
    return out


def find_kernel_config(build_dir: str | Path, machine: str | None = None) -> Path | None:
    """Look for a kernel ``.config`` in the usual places a build leaves one."""
    build = Path(build_dir)
    patterns = [
        f"tmp/deploy/images/{machine or '*'}/*.config",
        f"tmp/deploy/images/{machine or '*'}/config-*",
        "tmp/work/*/linux-*/*/build/.config",
        "tmp/work-shared/*/kernel-build-artifacts/.config",
        "tmp/work-shared/*/kernel-source/.config",
        # Buildroot
        "build/linux-*/.config",
        "output/build/linux-*/.config",
    ]
    for pattern in patterns:
        for candidate in sorted(build.glob(pattern)):
            if candidate.is_file():
                return candidate
    return None


def dedupe_licenses(values: list[str]) -> list[str]:
    seen: list[str] = []
    for v in values:
        v = (v or "").strip()
        if v and v not in seen:
            seen.append(v)
    return seen


def finish(product: Product) -> Product:
    """Normalisation every ingester should end with.

    ``scanned_at`` is stamped here, once, rather than at serialisation time:
    saving the same product twice has to produce identical bytes or the evidence
    ledger records a different hash for an inventory that did not change.
    """
    from .. import __version__

    product.components.sort(key=lambda c: c.name)
    product.cra24_version = __version__
    if not product.scanned_at:
        product.scanned_at = datetime.now(timezone.utc).isoformat()
    for comp in product.components:
        comp.licenses = dedupe_licenses(comp.licenses)
        comp.cpes = sorted(set(comp.cpes))
    return product
