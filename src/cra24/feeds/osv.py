# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""OSV — the open-source vulnerability database.

OSV answers the question the build tree cannot: **which versions are affected,
and which version fixes it**. That feeds rule 1 of the triage engine, the most
authoritative rule there is, because the ranges come from the people who fixed
the bug.

Two things make OSV awkward for embedded Linux, and both are handled here rather
than pretended away:

**Ecosystem mismatch.** OSV is organised by package ecosystem — PyPI, npm,
Debian, Alpine. A Yocto recipe belongs to none of them. So queries fall back to
name-only matching against the ``OSS-Fuzz``, ``Linux`` and unscoped records, and
the result is reported at lower confidence than a purl match would be.

**Range types.** A ``GIT`` range is expressed in commit hashes, which a version
string cannot be compared against. Those ranges are skipped rather than
misinterpreted; skipping is visible in the findings, misinterpreting would not be.

Unlike the other feeds, OSV is queried per package rather than bulk-downloaded,
so its cache is keyed by query.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from ..logging import get
from ..versions import in_range
from .base import Feed, FeedError

log = get("feeds.osv")

API = "https://api.osv.dev/v1"


@dataclass
class AffectedRange:
    introduced: str = ""
    fixed: str = ""
    last_affected: str = ""
    type: str = "ECOSYSTEM"

    def covers(self, version: str) -> bool:
        if self.type.upper() == "GIT":
            # Commit-hash ranges cannot be compared against a version string.
            return False
        return in_range(
            version,
            introduced=self.introduced or None,
            fixed=self.fixed or None,
            last_affected=self.last_affected or None,
        )


@dataclass
class OsvRecord:
    id: str
    aliases: tuple[str, ...] = ()
    summary: str = ""
    ranges: list[AffectedRange] = field(default_factory=list)
    versions: tuple[str, ...] = ()
    severity: str = ""
    ecosystems: tuple[str, ...] = ()

    @property
    def cve(self) -> str:
        if self.id.upper().startswith("CVE-"):
            return self.id.upper()
        for alias in self.aliases:
            if alias.upper().startswith("CVE-"):
                return alias.upper()
        return ""

    def fixed_version(self) -> str:
        """The lowest fixed version across the record's ranges, if any."""
        fixes = [r.fixed for r in self.ranges if r.fixed]
        if not fixes:
            return ""
        from ..versions import Version

        return str(min(Version(f) for f in fixes))

    def affects(self, version: str) -> bool:
        if self.versions and version in self.versions:
            return True
        return any(r.covers(version) for r in self.ranges)


def _parse_record(doc: dict[str, Any]) -> OsvRecord:
    ranges: list[AffectedRange] = []
    versions: list[str] = []
    ecosystems: list[str] = []

    for affected in doc.get("affected", []) or []:
        package = affected.get("package", {}) or {}
        if package.get("ecosystem"):
            ecosystems.append(package["ecosystem"])
        versions.extend(affected.get("versions", []) or [])
        for rng in affected.get("ranges", []) or []:
            rtype = (rng.get("type") or "ECOSYSTEM").upper()
            current = AffectedRange(type=rtype)
            for event in rng.get("events", []) or []:
                # Each event object carries exactly one of these keys. A "fixed"
                # closes the current interval, so it is emitted and a new one
                # started; otherwise a record with several intervals collapses
                # into one wrong one.
                if "introduced" in event:
                    if current.fixed or current.last_affected:
                        ranges.append(current)
                        current = AffectedRange(type=rtype)
                    current.introduced = event["introduced"]
                elif "fixed" in event:
                    current.fixed = event["fixed"]
                    ranges.append(current)
                    current = AffectedRange(type=rtype)
                elif "last_affected" in event:
                    current.last_affected = event["last_affected"]
                    ranges.append(current)
                    current = AffectedRange(type=rtype)
            if current.introduced or current.fixed or current.last_affected:
                ranges.append(current)

    severity = ""
    for entry in doc.get("severity", []) or []:
        if entry.get("score"):
            severity = f"{entry.get('type', '')} {entry['score']}".strip()
            break

    return OsvRecord(
        id=doc.get("id", ""),
        aliases=tuple(doc.get("aliases", []) or []),
        summary=doc.get("summary", "") or doc.get("details", "")[:200],
        ranges=ranges,
        versions=tuple(dict.fromkeys(versions)),
        severity=severity,
        ecosystems=tuple(dict.fromkeys(ecosystems)),
    )


class OsvFeed(Feed):
    name = "osv"
    host = "api.osv.dev"
    url = API
    filename = "index.json"  # unused; OSV is queried, not bulk-downloaded
    max_age = timedelta(days=7)
    purpose = "which versions are affected and which version fixes it"
    terms = (
        "OSV data is aggregated from upstream databases, each under its own terms; "
        "the OSV schema and service are Apache-2.0. Check the source database of a "
        "record before redistributing it."
    )

    def parse(self, raw: bytes) -> Any:
        return json.loads(raw)

    # -- per-CVE lookup ----------------------------------------------------

    def vuln(self, vuln_id: str, *, allow_fetch: bool = True) -> OsvRecord | None:
        """Fetch one record by id, caching the raw response."""
        vuln_id = (vuln_id or "").strip()
        if not vuln_id:
            return None
        name = f"vulns/{vuln_id.upper()}.json"
        if self.cache.has(self.name, name):
            return _parse_record(self.cache.read_json(self.name, name))
        if not allow_fetch:
            return None
        try:
            response = self.client.get(f"{API}/vulns/{vuln_id}")
        except FeedError as exc:
            log.info("OSV lookup for %s failed: %s", vuln_id, exc)
            return None
        self.cache.write(self.name, name, response.body, url=f"{API}/vulns/{vuln_id}")
        return _parse_record(response.json())

    # -- package query -----------------------------------------------------

    def query(
        self,
        package: str,
        version: str = "",
        *,
        ecosystem: str = "",
        purl: str = "",
        allow_fetch: bool = True,
    ) -> list[OsvRecord]:
        """Query by package name or purl, caching by the query itself."""
        payload: dict[str, Any] = {}
        if version:
            payload["version"] = version
        if purl:
            payload["package"] = {"purl": purl.split("?")[0]}
        else:
            pkg: dict[str, str] = {"name": package}
            if ecosystem:
                pkg["ecosystem"] = ecosystem
            payload["package"] = pkg

        key = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[
            :16
        ]
        name = f"query/{key}.json"

        if self.cache.has(self.name, name):
            doc = self.cache.read_json(self.name, name)
        elif not allow_fetch:
            return []
        else:
            try:
                response = self.client.post_json(f"{API}/query", payload)
            except FeedError as exc:
                log.info("OSV query for %s failed: %s", package, exc)
                return []
            self.cache.write(
                self.name, name, response.body, url=f"{API}/query", extra={"query": payload}
            )
            doc = response.json()

        return [_parse_record(v) for v in doc.get("vulns", []) or []]

    def status(self):  # type: ignore[override]
        from .base import FeedStatus

        root = self.cache.root / self.name
        count = len(list(root.rglob("*.json"))) if root.is_dir() else 0
        return FeedStatus(
            name=self.name,
            host=self.host,
            present=count > 0,
            fetched_at="",
            age_hours=None,
            fresh=count > 0,
            records=count,
            note=self.purpose + " (queried per package, not bulk-downloaded)",
        )
