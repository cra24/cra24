# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Canonical model: one shape every ingester fills and every emitter reads.

Ingesters (Yocto, Buildroot, CycloneDX, SPDX) fill it; emitters (SRP, CSAF,
OpenVEX, CycloneDX) render it. Adding a build system or an output format never
touches the other side.

The model deliberately keeps *why* alongside *what*. A component does not carry
"CVE-2024-1086: patched"; it carries a record saying the Yocto layer reported it
patched, in which file, and what justification string the recipe gave. Ten years
from now the justification is the part that matters, and it is the part every
tool throws away.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .versions import Version

CVE_RE = re.compile(
    r"^(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|EUVD-\d{4}-\d+)$", re.I
)

#: ISO 3166-1 alpha-2 codes of the EU Member States, for config validation.
EU_MEMBER_STATES = frozenset(
    {
        "AT",
        "BE",
        "BG",
        "HR",
        "CY",
        "CZ",
        "DK",
        "EE",
        "FI",
        "FR",
        "DE",
        "GR",
        "HU",
        "IE",
        "IT",
        "LV",
        "LT",
        "LU",
        "MT",
        "NL",
        "PL",
        "PT",
        "RO",
        "SK",
        "SI",
        "ES",
        "SE",
    }
)

ANNEX_CLASSES = ("default", "important-i", "important-ii", "critical")


class BuildStatus(str, Enum):
    """What the *build system* says about a CVE. Not a VEX status.

    The distinction matters. ``PATCHED`` means a layer applied a patch, which is
    evidence, not proof. Turning that into a published "not affected" is a human
    decision, and ``triage.py`` is where it happens.
    """

    PATCHED = "patched"
    IGNORED = "ignored"
    UNPATCHED = "unpatched"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value


@dataclass
class CveRecord:
    """One CVE as the build system reported it, with its provenance."""

    id: str
    status: BuildStatus = BuildStatus.UNKNOWN
    detail: str = ""
    source: str = ""
    fixed_version: str | None = None

    def __post_init__(self) -> None:
        self.id = (self.id or "").strip().upper()
        if isinstance(self.status, str):
            self.status = BuildStatus(self.status)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Component:
    """One package as it exists in the shipped image."""

    name: str
    version: str = ""
    purl: str | None = None
    cpes: list[str] = field(default_factory=list)
    licenses: list[str] = field(default_factory=list)
    arch: str = ""
    recipe: str = ""
    origin: str = "unknown"
    #: Binary packages this recipe produced that are installed in the image.
    #: Non-empty only when the component is tracked at recipe granularity,
    #: which is how Yocto's cve-check reports.
    provides: list[str] = field(default_factory=list)
    cves: dict[str, CveRecord] = field(default_factory=dict)
    #: Kernel config symbols that gate this component's vulnerable code.
    #: Populated by the kernel-config reader; consumed by triage. Empty means
    #: "no gating information", never "not gated".
    config_symbols: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        fixed: dict[str, CveRecord] = {}
        for key, rec in (self.cves or {}).items():
            if isinstance(rec, dict):
                rec = CveRecord(**rec)
            fixed[rec.id or str(key).upper()] = rec
        self.cves = fixed

    # -- convenience views -------------------------------------------------

    def record(self, cve: str) -> CveRecord | None:
        return self.cves.get((cve or "").strip().upper())

    def status(self, cve: str) -> BuildStatus:
        rec = self.record(cve)
        return rec.status if rec else BuildStatus.UNKNOWN

    def add_cve(
        self,
        cve_id: str,
        status: BuildStatus | str,
        *,
        detail: str = "",
        source: str = "",
        fixed_version: str | None = None,
    ) -> CveRecord:
        rec = CveRecord(
            id=cve_id,
            status=BuildStatus(status) if isinstance(status, str) else status,
            detail=detail,
            source=source,
            fixed_version=fixed_version,
        )
        if not rec.id:
            raise ConfigError("cannot add a CVE record with an empty id")
        existing = self.cves.get(rec.id)
        # A concrete status from any source beats a previously unknown one.
        if existing is None or existing.status is BuildStatus.UNKNOWN:
            self.cves[rec.id] = rec
        return self.cves[rec.id]

    def by_status(self, status: BuildStatus) -> list[CveRecord]:
        return sorted((r for r in self.cves.values() if r.status is status), key=lambda r: r.id)

    @property
    def patched_cves(self) -> list[str]:
        return [r.id for r in self.by_status(BuildStatus.PATCHED)]

    @property
    def unpatched_cves(self) -> list[str]:
        return [r.id for r in self.by_status(BuildStatus.UNPATCHED)]

    @property
    def ignored_cves(self) -> list[str]:
        return [r.id for r in self.by_status(BuildStatus.IGNORED)]

    @property
    def ver(self) -> Version:
        return Version(self.version)

    def identifier(self) -> str:
        """The best machine identifier available for this component."""
        return self.purl or f"pkg:generic/{self.name}@{self.version}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "cpes": sorted(self.cpes),
            "licenses": sorted(self.licenses),
            "arch": self.arch,
            "recipe": self.recipe,
            "origin": self.origin,
            "provides": sorted(self.provides),
            "config_symbols": sorted(self.config_symbols),
            "cves": {k: v.to_dict() for k, v in sorted(self.cves.items())},
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Component:
        d = dict(d)
        # Accept the flat 0.1 shape so an old product.json still loads.
        legacy = {
            BuildStatus.PATCHED: d.pop("patched_cves", None) or [],
            BuildStatus.IGNORED: d.pop("ignored_cves", None) or [],
            BuildStatus.UNPATCHED: d.pop("unpatched_cves", None) or [],
        }
        known = set(cls.__dataclass_fields__)
        comp = cls(**{k: v for k, v in d.items() if k in known})
        for status, ids in legacy.items():
            for cid in ids:
                comp.add_cve(cid, status, source="product.json (0.1 format)")
        return comp


@dataclass
class Manufacturer:
    """The entity placing the product on the EU market."""

    name: str = ""
    country: str = ""
    coordinator_csirt: str = ""
    assigned_representative: str = ""
    contact_email: str = ""
    security_contact_url: str = ""
    #: Namespace for CSAF documents you publish. Should be a domain you control.
    csaf_namespace: str = ""

    def validate(self) -> list[str]:
        gaps = []
        if not self.name:
            gaps.append("manufacturer.name")
        if not self.country:
            gaps.append("manufacturer.country")
        elif self.country.upper() not in EU_MEMBER_STATES:
            gaps.append(
                f"manufacturer.country ({self.country!r} is not an EU Member State code; "
                "if you are established outside the EU, name your authorised representative's state)"
            )
        if not self.coordinator_csirt:
            gaps.append("manufacturer.coordinator_csirt")
        if not self.contact_email:
            gaps.append("manufacturer.contact_email")
        return gaps


@dataclass
class Product:
    """A product with digital elements, as placed on the EU market."""

    name: str = ""
    version: str = ""
    machine: str = ""
    image: str = ""
    manufacturer: Manufacturer = field(default_factory=Manufacturer)
    components: list[Component] = field(default_factory=list)
    member_states: list[str] = field(default_factory=list)
    support_period_end: str = ""
    annex_class: str = "default"
    #: Free-text provenance: which build produced this inventory.
    build_id: str = ""
    scanned_at: str = ""
    #: Kernel config symbols set to =y or =m in the shipped kernel, if read.
    kernel_config: dict[str, str] = field(default_factory=dict)
    #: True when :data:`kernel_config` came from a kconfig-generated ``.config``,
    #: where every reachable symbol was considered and absence therefore means
    #: "not enabled". False for a defconfig or fragment, where absence means
    #: nothing and triage must not draw a conclusion from it.
    kernel_config_complete: bool = False
    cra24_version: str = ""

    # -- lookups -----------------------------------------------------------

    def find(self, name: str) -> Component | None:
        for c in self.components:
            if c.name == name:
                return c
        return None

    def __iter__(self) -> Iterator[Component]:
        return iter(self.components)

    def __len__(self) -> int:
        return len(self.components)

    def bearing(self, cve: str) -> list[tuple[Component, CveRecord]]:
        """Components carrying this CVE, with the build's own record for it."""
        cve = (cve or "").strip().upper()
        out = []
        for c in self.components:
            rec = c.record(cve)
            if rec is not None:
                out.append((c, rec))
        return sorted(out, key=lambda pair: pair[0].name)

    def all_cves(self) -> dict[str, list[Component]]:
        index: dict[str, list[Component]] = {}
        for c in self.components:
            for cve_id in c.cves:
                index.setdefault(cve_id, []).append(c)
        return index

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in BuildStatus}
        for c in self.components:
            for rec in c.cves.values():
                out[rec.status.value] += 1
        out["components"] = len(self.components)
        return out

    # -- validation --------------------------------------------------------

    def validate(self) -> list[str]:
        """Return the list of reporting gaps. Empty means ready to report."""
        gaps = self.manufacturer.validate()
        if not self.name:
            gaps.append("name")
        if not self.version:
            gaps.append("version (the SRP asks for product version as its own field)")
        if not self.member_states:
            gaps.append(
                "member_states (Article 14(1)(a): the early warning shall "
                "indicate the Member States where the product is available)"
            )
        else:
            bad = [m for m in self.member_states if m.upper() not in EU_MEMBER_STATES]
            if bad:
                gaps.append(f"member_states contains non-EU codes: {', '.join(sorted(bad))}")
        if self.annex_class not in ANNEX_CLASSES:
            gaps.append(f"annex_class must be one of {', '.join(ANNEX_CLASSES)}")
        if not self.components:
            gaps.append("components (nothing was ingested; the dossier would be empty)")
        return gaps

    # -- serialisation -----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "machine": self.machine,
            "image": self.image,
            "manufacturer": asdict(self.manufacturer),
            "member_states": [m.upper() for m in self.member_states],
            "support_period_end": self.support_period_end,
            "annex_class": self.annex_class,
            "build_id": self.build_id,
            # Never invent a timestamp here. Serialising the same product twice
            # must produce the same bytes, or the evidence ledger records a
            # different hash for an inventory that did not change.
            "scanned_at": self.scanned_at,
            "kernel_config": dict(sorted(self.kernel_config.items())),
            "kernel_config_complete": self.kernel_config_complete,
            "cra24_version": self.cra24_version,
            "components": [c.to_dict() for c in sorted(self.components, key=lambda c: c.name)],
        }

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        if p.parent != Path():
            p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return p

    @classmethod
    def load(cls, path: str | Path) -> Product:
        p = Path(path)
        if not p.is_file():
            raise ConfigError(
                f"{p} does not exist",
                hint="run `cra24 scan` first, or point --product at the file it wrote",
            )
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{p} is not valid JSON: {exc}") from exc
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Product:
        d = dict(d)
        manufacturer = Manufacturer(
            **{
                k: v
                for k, v in (d.pop("manufacturer", None) or {}).items()
                if k in Manufacturer.__dataclass_fields__
            }
        )
        components = [Component.from_dict(c) for c in d.pop("components", None) or []]
        known = set(cls.__dataclass_fields__)
        unknown = sorted(set(d) - known)
        if unknown:
            raise ConfigError(
                f"unrecognised keys in product data: {', '.join(unknown)}",
                hint="a typo here silently drops data; fix the file rather than ignoring it",
            )
        return cls(
            manufacturer=manufacturer,
            components=components,
            **{k: v for k, v in d.items() if k in known},
        )
