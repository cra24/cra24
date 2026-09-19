# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Read a Buildroot output tree.

Buildroot scatters the same information Yocto keeps in one place:

``output/legal-info/manifest.csv``
    Produced by ``make legal-info``. The inventory: package, version, licence,
    source site. This is the closest thing Buildroot has to an image manifest.

``output/pkg-stats.json``
    Produced by ``make pkg-stats``. Carries CVE and CPE data per package, with
    ``ignore_cves`` reflecting the ``<PKG>_IGNORE_CVES`` variable — Buildroot's
    equivalent of Yocto's ``CVE_STATUS``, and the only vulnerability triage
    signal the tree contains.

``output/build/linux-*/.config``
    The kernel configuration, for gating.

If ``legal-info`` was never run the ingest falls back to ``pkg-stats.json``
alone, and says so, because pkg-stats covers packages that were *enabled*, which
is a superset of what the final image contains.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .. import purl as purl_mod
from ..errors import IngestError
from ..logging import get
from ..model import BuildStatus, Component, Product
from .base import find_kernel_config, finish, is_generated_config, read_kernel_config

log = get("ingest.buildroot")


def _output_dir(root: Path) -> Path:
    """Accept either the Buildroot source root or an output directory."""
    if (root / "legal-info").is_dir() or (root / "build").is_dir():
        return root
    if (root / "output").is_dir():
        return root / "output"
    return root


def _from_manifest(out: Path) -> dict[str, Component]:
    manifest = out / "legal-info" / "manifest.csv"
    comps: dict[str, Component] = {}
    if not manifest.is_file():
        return comps
    with manifest.open(newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            name = (row.get("PACKAGE") or "").strip()
            if not name:
                continue
            version = (row.get("VERSION") or "").strip()
            licenses = [p.strip() for p in (row.get("LICENSE") or "").split(",") if p.strip()]
            comps[name] = Component(
                name=name,
                version=version,
                licenses=licenses,
                origin="buildroot:legal-info",
                purl=purl_mod.for_component(name, version, "buildroot"),
            )
    return comps


def _apply_pkg_stats(out: Path, comps: dict[str, Component], inventory_known: bool) -> int:
    stats = out / "pkg-stats.json"
    if not stats.is_file():
        for candidate in sorted(out.glob("**/pkg-stats.json")):
            stats = candidate
            break
    if not stats.is_file():
        return 0

    data = json.loads(stats.read_text(errors="replace"))
    packages = data.get("packages", {})
    if isinstance(packages, list):
        packages = {p.get("name", ""): p for p in packages if p.get("name")}

    records = 0
    for name, info in packages.items():
        if not name:
            continue
        comp = comps.get(name)
        if comp is None:
            if inventory_known:
                # Enabled but not in the image manifest: do not claim it ships.
                continue
            comp = Component(
                name=name,
                version=(info.get("version") or "").strip(),
                origin="buildroot:pkg-stats",
                purl=purl_mod.for_component(name, info.get("version") or "", "buildroot"),
            )
            comps[name] = comp
        if not comp.version and info.get("version"):
            comp.version = str(info["version"]).strip()
        for cpe in info.get("cpes", []) or ([info["cpeid"]] if info.get("cpeid") else []):
            if cpe:
                comp.cpes.append(str(cpe))

        ignored = {str(c).upper() for c in (info.get("ignore_cves") or [])}
        for cve_id in ignored:
            comp.add_cve(
                cve_id,
                BuildStatus.IGNORED,
                detail="ignored: listed in <PKG>_IGNORE_CVES",
                source="buildroot:pkg-stats.json",
            )
            records += 1
        for cve_id in info.get("cves") or []:
            cve_id = str(cve_id).upper()
            if cve_id in ignored:
                continue
            comp.add_cve(cve_id, BuildStatus.UNPATCHED, source="buildroot:pkg-stats.json")
            records += 1
    return records


def load_buildroot(
    root: str | Path,
    product_name: str = "",
    product_version: str = "",
    kernel_config: str | Path | None = None,
) -> Product:
    """Build a :class:`Product` from a Buildroot tree."""
    base = Path(root)
    if not base.is_dir():
        raise IngestError(f"{base} is not a directory")
    out = _output_dir(base)

    comps = _from_manifest(out)
    inventory_known = bool(comps)
    if inventory_known:
        log.info("read %d packages from legal-info/manifest.csv", len(comps))

    records = _apply_pkg_stats(out, comps, inventory_known)
    log.info("read %d CVE records from pkg-stats.json", records)

    if not comps:
        raise IngestError(
            f"found no components under {out}",
            hint="run `make legal-info` for the inventory and `make pkg-stats` for "
            "CVE data, then point --buildroot-dir at the output directory",
        )
    if not inventory_known:
        log.warning(
            "no legal-info manifest: the inventory comes from pkg-stats, which "
            "lists enabled packages rather than installed ones. Run "
            "`make legal-info` before relying on this for a filing."
        )

    product = Product(
        name=product_name or base.resolve().name,
        version=product_version,
        components=list(comps.values()),
        build_id=str(base.resolve()),
    )

    cfg_path = Path(kernel_config) if kernel_config else find_kernel_config(base)
    if cfg_path and Path(cfg_path).is_file():
        product.kernel_config = read_kernel_config(cfg_path)
        product.kernel_config_complete = is_generated_config(cfg_path)
        log.info(
            "read %d kernel config symbols from %s%s",
            len(product.kernel_config),
            cfg_path,
            ""
            if product.kernel_config_complete
            else " (not kconfig-generated; gating limited)",
        )
    elif kernel_config:
        raise IngestError(f"kernel config {kernel_config} not found")

    return finish(product)
