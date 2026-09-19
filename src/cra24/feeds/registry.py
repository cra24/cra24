# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Putting the feeds together into one answer the triage engine can use.

The rule this module exists to enforce: **feed data fills the arguments
``triage()`` already takes; it never overrides your own decision.** Each fact
carries the feed that supplied it, and every one of them lands in the dossier's
evidence trail with its source named. If a verdict changed because CISA added a
CVE to KEV this morning, the dossier says so.

The one judgement call worth stating explicitly:

    presence in KEV  →  actively_exploited = True
    absence from KEV →  actively_exploited = unknown, never False

KEV is a conservative, curated, US federal list. Presence is strong evidence.
Absence means CISA has not confirmed exploitation, which is not the same as
confirming there is none — and a customer telling you your product is being
attacked starts the 24-hour clock whether or not CISA has heard of it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..logging import get
from ..model import Component, Product
from .base import Feed, FeedStatus, HttpClient, OfflineError
from .cache import Cache
from .epss import EpssFeed
from .euvd import EuvdFeed
from .kev import KevFeed
from .nvd import NvdFeed
from .osv import OsvFeed

log = get("feeds.registry")

#: Feeds contacted by default. NVD and OSV are per-CVE lookups rather than bulk
#: downloads, so they are not synced; they populate their cache on use.
BULK_FEEDS = ("kev", "epss", "euvd")
ALL_FEEDS = ("kev", "epss", "osv", "nvd", "euvd")


@dataclass
class Evidence:
    """One fact a feed supplied, with the feed that supplied it."""

    source: str
    statement: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "statement": self.statement, "detail": self.detail}


@dataclass
class Enrichment:
    """Everything the feeds know about one CVE, in the shape triage wants."""

    cve: str
    actively_exploited: bool | None = None
    fixed_version: str = ""
    introduced: str = ""
    last_affected: str = ""
    epss: float | None = None
    epss_percentile: float | None = None
    severity: str = ""
    cvss_vector: str = ""
    cvss_score: float | None = None
    cvss_version: str = ""
    euvd_id: str = ""
    aliases: tuple[str, ...] = ()
    description: str = ""
    ransomware: bool = False
    evidence: list[Evidence] = field(default_factory=list)
    consulted: list[str] = field(default_factory=list)
    offline: bool = False

    def note(self, source: str, statement: str, detail: str = "") -> None:
        self.evidence.append(Evidence(source, statement, detail))

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "actively_exploited": self.actively_exploited,
            "fixed_version": self.fixed_version,
            "introduced": self.introduced,
            "last_affected": self.last_affected,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "severity": self.severity,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version,
            "euvd_id": self.euvd_id,
            "aliases": list(self.aliases),
            "ransomware": self.ransomware,
            "consulted": self.consulted,
            "offline": self.offline,
            "evidence": [e.to_dict() for e in self.evidence],
        }

    def summary(self) -> str:
        bits = []
        if self.actively_exploited is True:
            bits.append("actively exploited")
        elif self.actively_exploited is None:
            bits.append("exploitation unknown")
        if self.severity:
            bits.append(f"severity {self.severity}")
        if self.epss is not None:
            bits.append(f"EPSS {self.epss:.4f}")
        if self.fixed_version:
            bits.append(f"fixed in {self.fixed_version}")
        return ", ".join(bits) if bits else "no feed data"


class FeedSet:
    """The feeds a run is allowed to consult."""

    def __init__(
        self,
        names: list[str] | tuple[str, ...] | None = None,
        *,
        cache: Cache | None = None,
        offline: bool = False,
    ) -> None:
        self.cache = cache or Cache()
        self.offline = offline
        self.names = tuple(names) if names else ALL_FEEDS
        client = HttpClient(offline=offline)
        builders = {
            "kev": lambda: KevFeed(self.cache, client),
            "epss": lambda: EpssFeed(self.cache, client),
            "osv": lambda: OsvFeed(self.cache, client),
            "euvd": lambda: EuvdFeed(self.cache, client),
            # NVD builds its own rate-limited client unless one is forced.
            "nvd": lambda: NvdFeed(self.cache, client if offline else None),
        }
        unknown = [n for n in self.names if n not in builders]
        if unknown:
            from ..errors import ConfigError

            raise ConfigError(
                f"unknown feed(s): {', '.join(unknown)}",
                hint="available: " + ", ".join(ALL_FEEDS),
            )
        self.feeds: dict[str, Feed] = {n: builders[n]() for n in self.names}

    def __contains__(self, name: str) -> bool:
        return name in self.feeds

    def get(self, name: str) -> Feed | None:
        return self.feeds.get(name)

    # -- lifecycle ---------------------------------------------------------

    def sync(self, *, force: bool = False) -> list[FeedStatus]:
        out = []
        for name in self.names:
            if name not in BULK_FEEDS:
                out.append(self.feeds[name].status())
                continue
            try:
                out.append(self.feeds[name].sync(force=force))
            except OfflineError:
                raise
            except Exception as exc:
                log.warning("%s sync failed: %s", name, exc)
                status = self.feeds[name].status()
                status.note = f"sync failed: {exc}"
                out.append(status)
        return out

    def status(self) -> list[FeedStatus]:
        return [self.feeds[n].status() for n in self.names]

    # -- the thing triage wants -------------------------------------------

    def enrich(self, cve: str, component: Component | None = None) -> Enrichment:
        cve = (cve or "").strip().upper()
        result = Enrichment(cve=cve, offline=self.offline)

        kev = self.feeds.get("kev")
        if isinstance(kev, KevFeed) and kev.available():
            result.consulted.append("kev")
            entry = kev.lookup(cve)
            if entry is not None:
                result.actively_exploited = True
                result.ransomware = entry.ransomware
                result.note("cisa-kev", "actively exploited", entry.summary())
                if not result.description:
                    result.description = entry.short_description
            else:
                result.note(
                    "cisa-kev",
                    "not listed",
                    "absence is not evidence of no exploitation; KEV is conservative "
                    "and US-federal, so this leaves the Article 14(1) trigger unknown",
                )

        euvd = self.feeds.get("euvd")
        if isinstance(euvd, EuvdFeed) and euvd.available():
            result.consulted.append("euvd")
            record = euvd.exploited(cve)
            if record is not None:
                if result.actively_exploited is not True:
                    result.actively_exploited = True
                result.note("enisa-euvd", "listed by ENISA as exploited", record.summary())
                # The exploited list already carries the EUVD id and the score,
                # so take them here rather than making a second lookup that
                # would need a network on a machine that may not have one.
                result.euvd_id = result.euvd_id or record.id
                if record.base_score is not None and result.cvss_score is None:
                    result.cvss_score = record.base_score
                    result.cvss_version = record.base_score_version
                    result.cvss_vector = record.base_score_vector
                if record.aliases:
                    result.aliases = tuple(dict.fromkeys(result.aliases + record.aliases))
            cached = euvd.lookup(cve, allow_fetch=not self.offline)
            if cached is not None:
                result.euvd_id = cached.id or result.euvd_id
                if cached.base_score is not None and result.cvss_score is None:
                    result.cvss_score = cached.base_score
                    result.cvss_version = cached.base_score_version
                    result.cvss_vector = cached.base_score_vector
                if cached.id:
                    result.note(
                        "enisa-euvd",
                        f"EUVD id {cached.id}",
                        "fills the SRP's optional EUVD field",
                    )

        epss = self.feeds.get("epss")
        if isinstance(epss, EpssFeed) and epss.available():
            result.consulted.append("epss")
            score = epss.lookup(cve)
            if score is not None:
                result.epss = score.probability
                result.epss_percentile = score.percentile
                result.note(
                    "epss",
                    score.summary(),
                    "a prediction, for ordering your queue — never evidence of "
                    "active exploitation",
                )

        nvd = self.feeds.get("nvd")
        if isinstance(nvd, NvdFeed):
            nvd_record = nvd.lookup(cve, allow_fetch=not self.offline)
            if nvd_record is not None:
                result.consulted.append("nvd")
                result.severity = result.severity or nvd_record.severity_word()
                if result.cvss_score is None:
                    result.cvss_score = nvd_record.base_score
                    result.cvss_vector = nvd_record.cvss_vector
                    result.cvss_version = nvd_record.cvss_version
                result.description = result.description or nvd_record.description
                result.note("nvd", nvd_record.summary())

        osv = self.feeds.get("osv")
        if isinstance(osv, OsvFeed) and component is not None:
            records = osv.query(
                component.name,
                component.version,
                purl=component.purl or "",
                allow_fetch=not self.offline,
            )
            if records:
                result.consulted.append("osv")
            for osv_record in records:
                if osv_record.cve and osv_record.cve != cve and cve not in osv_record.aliases:
                    continue
                fixed = osv_record.fixed_version()
                if fixed and not result.fixed_version:
                    result.fixed_version = fixed
                    result.note("osv", f"fixed in {fixed}", f"from {osv_record.id}")
                for rng in osv_record.ranges:
                    if rng.introduced and not result.introduced:
                        result.introduced = rng.introduced
                    if rng.last_affected and not result.last_affected:
                        result.last_affected = rng.last_affected
                if osv_record.aliases:
                    result.aliases = tuple(dict.fromkeys(result.aliases + osv_record.aliases))

        if not result.consulted:
            result.note(
                "feeds",
                "no feed data available",
                "run `cra24 feeds sync` where there is a network, or copy a "
                "populated cache across",
            )
        return result


def enrich(
    cve: str,
    component: Component | None = None,
    *,
    feeds: FeedSet | None = None,
    offline: bool = False,
) -> Enrichment:
    """Convenience wrapper for a one-off lookup."""
    return (feeds or FeedSet(offline=offline)).enrich(cve, component)


def best_component(product: Product, cve: str) -> Component | None:
    """The component most worth asking OSV about for this CVE."""
    bearing = product.bearing(cve)
    if not bearing:
        return None
    for comp, record in bearing:
        if record.status.value == "unpatched":
            return comp
    return bearing[0][0]
