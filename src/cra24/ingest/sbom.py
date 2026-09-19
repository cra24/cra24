# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Ingest an SBOM someone already produced: CycloneDX 1.x or SPDX 2.x / 3.x JSON.

This is the path for a product whose build system is not Yocto or Buildroot, and
the path for a component you received from a supplier. Two things matter here
that most SBOM readers skip:

* **CycloneDX ``vulnerabilities``** — when the SBOM carries them, the ``analysis``
  block is a VEX statement already. Reading it preserves triage decisions someone
  else made rather than starting from zero.
* **The distinction between a component that is present and a component that is
  merely referenced.** An SBOM lists everything it describes; only some of it
  ships. Where the document marks scope, it is honoured.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..errors import IngestError
from ..logging import get
from ..model import BuildStatus, Component, Product
from .base import finish

log = get("ingest.sbom")

#: CycloneDX ``analysis.state`` -> our BuildStatus.
_CDX_STATE = {
    "resolved": BuildStatus.PATCHED,
    "resolved_with_pedigree": BuildStatus.PATCHED,
    "not_affected": BuildStatus.IGNORED,
    "false_positive": BuildStatus.IGNORED,
    "exploitable": BuildStatus.UNPATCHED,
    "in_triage": BuildStatus.UNKNOWN,
}


def _cdx_licenses(entry: dict[str, Any]) -> list[str]:
    out = []
    for item in entry.get("licenses", []) or []:
        lic = item.get("license", {}) if isinstance(item, dict) else {}
        value = (
            lic.get("id")
            or lic.get("name")
            or (item.get("expression") if isinstance(item, dict) else "")
        )
        if value:
            out.append(str(value))
    return out


def _spdx_purl(refs: list[dict[str, Any]]) -> str | None:
    for ref in refs or []:
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def _spdx_cpes(refs: list[dict[str, Any]]) -> list[str]:
    return [
        r["referenceLocator"]
        for r in refs or []
        if str(r.get("referenceType", "")).startswith("cpe") and r.get("referenceLocator")
    ]


def _load_cyclonedx(doc: dict[str, Any]) -> tuple[list[Component], dict[str, Any]]:
    comps: dict[str, Component] = {}
    for entry in doc.get("components", []) or []:
        name = (entry.get("name") or "").strip()
        if not name:
            continue
        version = (entry.get("version") or "").strip()
        cpes = [entry["cpe"]] if entry.get("cpe") else []
        comps[entry.get("bom-ref") or name] = Component(
            name=name,
            version=version,
            purl=entry.get("purl"),
            cpes=cpes,
            licenses=_cdx_licenses(entry),
            origin="cyclonedx",
        )

    by_name = {c.name: c for c in comps.values()}

    for vuln in doc.get("vulnerabilities", []) or []:
        cve_id = (vuln.get("id") or "").strip()
        if not cve_id:
            continue
        analysis = vuln.get("analysis", {}) or {}
        state = str(analysis.get("state", "")).lower()
        status = _CDX_STATE.get(state, BuildStatus.UNPATCHED)
        detail_parts = [p for p in (analysis.get("justification"), analysis.get("detail")) if p]
        detail = ": ".join(str(p) for p in detail_parts)
        targets = vuln.get("affects", []) or []
        if not targets:
            continue
        for affect in targets:
            ref = affect.get("ref")
            comp = comps.get(ref) or by_name.get(str(ref).split("@")[0])
            if comp is None:
                continue
            comp.add_cve(cve_id, status, detail=detail, source="cyclonedx:vulnerabilities")

    meta = doc.get("metadata", {}) or {}
    return list(comps.values()), meta


def _load_spdx(doc: dict[str, Any]) -> tuple[list[Component], dict[str, Any]]:
    comps: list[Component] = []
    for pkg in doc.get("packages", []) or []:
        name = (pkg.get("name") or "").strip()
        if not name:
            continue
        refs = pkg.get("externalRefs", []) or []
        declared = pkg.get("licenseDeclared") or ""
        concluded = pkg.get("licenseConcluded") or ""
        licenses = [v for v in (declared, concluded) if v and v not in ("NOASSERTION", "NONE")]
        comps.append(
            Component(
                name=name,
                version=(pkg.get("versionInfo") or "").strip(),
                purl=_spdx_purl(refs),
                cpes=_spdx_cpes(refs),
                licenses=licenses,
                origin="spdx",
            )
        )
    return comps, {"spdxVersion": doc.get("spdxVersion", "")}


def load_sbom(path: str | Path, product_name: str = "", product_version: str = "") -> Product:
    """Build a :class:`Product` from a CycloneDX or SPDX JSON document."""
    p = Path(path)
    if not p.is_file():
        raise IngestError(f"{p} does not exist")
    try:
        doc = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise IngestError(
            f"{p} is not valid JSON: {exc}",
            hint="cra24 reads JSON SBOMs; convert XML or tag-value first",
        ) from exc
    if not isinstance(doc, dict):
        raise IngestError(f"{p} does not contain an SBOM document")

    name = product_name
    version = product_version

    if doc.get("bomFormat") == "CycloneDX" or ("components" in doc and "packages" not in doc):
        components, meta = _load_cyclonedx(doc)
        target = (meta.get("component") or {}) if isinstance(meta, dict) else {}
        name = name or (target.get("name") or "")
        version = version or (target.get("version") or "")
        fmt = f"CycloneDX {doc.get('specVersion', '')}".strip()
    elif "packages" in doc or "spdxVersion" in doc:
        components, meta = _load_spdx(doc)
        name = name or (doc.get("name") or "")
        fmt = meta.get("spdxVersion") or "SPDX"
    else:
        raise IngestError(
            f"{p} is neither CycloneDX nor SPDX",
            hint="expected a top-level 'bomFormat' of CycloneDX, or an SPDX "
            "document with a 'packages' array",
        )

    if not components:
        raise IngestError(f"{p} describes no components")

    log.info("read %d components from %s", len(components), fmt)
    return finish(
        Product(
            name=name or p.stem,
            version=version,
            components=components,
            build_id=f"{fmt}:{p.name}",
        )
    )
