# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Read what a Yocto or OpenEmbedded build already wrote. No bitbake, no rebuild.

Sources, in order of usefulness:

``tmp/log/cve/cve-summary.json``
    ``cve-check`` output. The most valuable file in the tree, because it already
    knows which CVEs the layers patched and — in releases from scarthgap onward —
    *why*, in the ``detail`` field carrying the ``CVE_STATUS`` reason. That
    reason string is the difference between a 500-line CVE list and the handful
    that actually ship, and it is what ``triage.py`` reads.

``tmp/deploy/images/<machine>/*.manifest``
    The package list actually installed in the image. Authoritative for what
    ships; says nothing about vulnerabilities.

``tmp/deploy/licenses/**/license.manifest``
    Per-recipe licence and version data, useful when the image manifest is thin.

``tmp/deploy/images/<machine>/*.json``
    Per-image cve-check output on builds configured to deploy it there.

A component that appears in cve-check but not in the image manifest is recorded
with ``origin=yocto:cve-summary`` and flagged, because cve-check runs over recipes
that were *built*, and a recipe can be built without being installed. Treating
those as shipped is the most common way a CRA inventory ends up overstating what
is on the device.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import purl as purl_mod
from ..errors import IngestError
from ..logging import get
from ..model import BuildStatus, Component, Product
from .base import find_kernel_config, finish, is_generated_config, read_kernel_config

log = get("ingest.yocto")

#: cve-check status string -> our BuildStatus.
_STATUS_MAP = {
    "patched": BuildStatus.PATCHED,
    "ignored": BuildStatus.IGNORED,
    "unpatched": BuildStatus.UNPATCHED,
    "unknown": BuildStatus.UNKNOWN,
}


def _image_manifests(build: Path, machine: str | None) -> list[Path]:
    images = build / "tmp" / "deploy" / "images"
    if not images.is_dir():
        return []
    roots = [images / machine] if machine else sorted(p for p in images.iterdir() if p.is_dir())
    out: list[Path] = []
    for root in roots:
        if root.is_dir():
            out.extend(sorted(root.glob("*.manifest")))
    return out


def _from_manifests(build: Path, machine: str | None) -> dict[str, Component]:
    comps: dict[str, Component] = {}
    for man in _image_manifests(build, machine):
        for line in man.read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            name, arch, version = parts[0], parts[1], parts[2]
            existing = comps.get(name)
            if existing is None:
                comps[name] = Component(
                    name=name,
                    version=version,
                    arch=arch,
                    origin=f"yocto:{man.name}",
                    purl=purl_mod.for_component(name, version, "yocto", arch=arch),
                )
            elif not existing.arch:
                existing.arch = arch
    return comps


def _cve_summary_files(build: Path, machine: str | None) -> list[Path]:
    out = []
    primary = build / "tmp" / "log" / "cve" / "cve-summary.json"
    if primary.is_file():
        out.append(primary)
    images = build / "tmp" / "deploy" / "images"
    if images.is_dir():
        roots = (
            [images / machine] if machine else sorted(p for p in images.iterdir() if p.is_dir())
        )
        for root in roots:
            if root.is_dir():
                out.extend(sorted(root.glob("*.json")))
    return out


def _looks_like_cve_summary(data: Any) -> bool:
    return isinstance(data, dict) and isinstance(data.get("package"), list)


def _apply_cve_summary(
    path: Path,
    comps: dict[str, Component],
    shipped: set[str],
    recipe_packages: dict[str, set[str]],
) -> int:
    try:
        data = json.loads(path.read_text(errors="replace"))
    except json.JSONDecodeError:
        log.debug("skipping %s: not JSON", path)
        return 0
    if not _looks_like_cve_summary(data):
        return 0

    added = 0
    for pkg in data.get("package", []):
        name = (pkg.get("name") or "").strip()
        if not name:
            continue
        version = (pkg.get("version") or "").strip()
        comp = comps.get(name)
        if comp is not None:
            # cve-check named an installed package directly.
            shipped.add(name)
            if not comp.version:
                comp.version = version
            if not comp.recipe:
                comp.recipe = name
        else:
            # cve-check reports at *recipe* granularity; image manifests list
            # *packages*. linux-raspberrypi ships as kernel-image-image, and
            # dropping the recipe because its own name is absent from the
            # manifest is how a kernel CVE silently disappears from a dossier.
            produced = recipe_packages.get(name, set())
            installed = sorted(produced & shipped_packages(comps))
            comp = Component(
                name=name,
                version=version,
                recipe=name,
                provides=installed,
                origin="yocto:cve-summary",
                purl=purl_mod.for_component(name, version, "yocto"),
            )
            comps[name] = comp
            if installed:
                shipped.add(name)

        for issue in pkg.get("issue", []) or []:
            cid = (issue.get("id") or "").strip()
            if not cid:
                continue
            raw_status = (issue.get("status") or "").strip().lower()
            status = _STATUS_MAP.get(raw_status, BuildStatus.UNKNOWN)
            # ``detail`` carries the CVE_STATUS reason (not-applicable-config,
            # backported-patch, …) on releases that record it. ``description``
            # carries the human justification the recipe author wrote.
            detail = (issue.get("detail") or "").strip()
            description = (issue.get("description") or "").strip()
            if detail and description:
                detail = f"{detail}: {description}"
            elif not detail and description:
                detail = description
            comp.add_cve(cid, status, detail=detail, source=f"yocto:{path.name}")
            added += 1
    return added


def shipped_packages(comps: dict[str, Component]) -> set[str]:
    """Names that came from an image manifest, i.e. actually installed."""
    return {
        n
        for n, c in comps.items()
        if c.origin.startswith("yocto:")
        and not c.origin.endswith("cve-summary")
        and not c.origin.endswith("license.manifest")
    }


def _apply_licenses(build: Path, comps: dict[str, Component]) -> dict[str, set[str]]:
    """Attach licences, and return the recipe -> packages map the tree records."""
    recipe_packages: dict[str, set[str]] = {}
    root = build / "tmp" / "deploy" / "licenses"
    if not root.is_dir():
        return recipe_packages
    for man in sorted(root.rglob("license.manifest")):
        name = version = None
        for line in man.read_text(errors="replace").splitlines():
            line = line.strip()
            if line.startswith("PACKAGE NAME:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("PACKAGE VERSION:"):
                version = line.split(":", 1)[1].strip()
            elif line.startswith("RECIPE NAME:") and name:
                recipe = line.split(":", 1)[1].strip()
                recipe_packages.setdefault(recipe, set()).add(name)
                comp = comps.get(name)
                if comp is not None and not comp.recipe:
                    comp.recipe = recipe
            elif line.startswith("LICENSE:") and name:
                lic = line.split(":", 1)[1].strip()
                comp = comps.get(name)
                if comp is None:
                    comp = Component(
                        name=name,
                        version=version or "",
                        origin="yocto:license.manifest",
                        purl=purl_mod.for_component(name, version or "", "yocto"),
                    )
                    comps[name] = comp
                if lic:
                    comp.licenses.append(lic)
                name = version = None
    return recipe_packages


def load_yocto(
    build_dir: str | Path,
    machine: str | None = None,
    product_name: str = "",
    product_version: str = "",
    kernel_config: str | Path | None = None,
    include_unshipped: bool = False,
) -> Product:
    """Build a :class:`Product` from an existing Yocto build directory."""
    build = Path(build_dir)
    if not build.is_dir():
        raise IngestError(f"{build} is not a directory")
    if not (build / "tmp").is_dir():
        raise IngestError(
            f"{build} does not look like a Yocto build directory (no tmp/)",
            hint="point --build-dir at the directory bitbake writes into, "
            "the one containing conf/ and tmp/",
        )

    comps = _from_manifests(build, machine)
    shipped = set(comps)
    log.info("read %d packages from image manifests", len(comps))

    # Licences first: the RECIPE NAME lines give the recipe -> package map that
    # lets a recipe-level CVE record be matched to an installed package.
    recipe_packages = _apply_licenses(build, comps)
    log.debug("mapped %d recipes to installed packages", len(recipe_packages))

    records = 0
    summaries = _cve_summary_files(build, machine)
    for path in summaries:
        records += _apply_cve_summary(path, comps, shipped, recipe_packages)
    log.info("read %d CVE records from %d file(s)", records, len(summaries))

    if not comps:
        raise IngestError(
            "found no components in this build tree",
            hint="check that tmp/deploy/images/<machine>/*.manifest exists, and "
            'that cve-check ran (INHERIT += "cve-check") so '
            "tmp/log/cve/cve-summary.json is present",
        )

    if not include_unshipped and shipped:
        dropped = [
            n for n, c in comps.items() if c.origin == "yocto:cve-summary" and n not in shipped
        ]
        for name in dropped:
            del comps[name]
        if dropped:
            log.info(
                "dropped %d recipe(s) built but not installed in the image: %s",
                len(dropped),
                ", ".join(sorted(dropped)[:10]),
            )

    product = Product(
        name=product_name or build.resolve().name,
        version=product_version,
        machine=machine or "",
        components=list(comps.values()),
        build_id=str(build.resolve()),
    )

    cfg_path = Path(kernel_config) if kernel_config else find_kernel_config(build, machine)
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

    images = sorted({m.stem for m in _image_manifests(build, machine)})
    if images:
        product.image = images[0]

    return finish(product)
