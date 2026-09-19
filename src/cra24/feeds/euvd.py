# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""EUVD — ENISA's European Vulnerability Database.

Two reasons this feed is here, and the second is the interesting one.

**It supplies the EUVD identifier.** The SRP has an EUVD field. It is optional,
and almost nobody fills it, which means a CSIRT receiving your notification has
to do the CVE-to-EUVD mapping themselves. Filling a field your coordinator would
otherwise fill by hand, at 2am, is cheap goodwill.

**It is EU-hosted infrastructure for an EU obligation.** ENISA publishes its own
exploited-vulnerability list at ``/api/exploitedvulnerabilities`` and a KEV dump
at ``/api/kev/dump``. For a manufacturer who would rather not have their
compliance tooling depend on a US federal feed — a reasonable position, and one
that comes up in procurement — this is the alternative. cra24 will use either or
both, and records which one said what.

The API is young and undocumented in places; every call degrades to "no data"
rather than failing a triage run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from ..logging import get
from .base import Feed, FeedError

log = get("feeds.euvd")

API = "https://euvdservices.enisa.europa.eu/api"


@dataclass
class EuvdRecord:
    id: str = ""
    cve: str = ""
    description: str = ""
    published: str = ""
    updated: str = ""
    base_score: float | None = None
    base_score_version: str = ""
    base_score_vector: str = ""
    epss: float | None = None
    aliases: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    vendors: tuple[str, ...] = ()
    products: tuple[str, ...] = ()
    exploited: bool = False

    def summary(self) -> str:
        bits = [f"EUVD {self.id}"] if self.id else []
        if self.base_score is not None:
            bits.append(f"CVSS {self.base_score_version} {self.base_score}")
        if self.exploited:
            bits.append("listed by ENISA as exploited")
        return ", ".join(bits)


def _split_lines(value: Any) -> tuple[str, ...]:
    """Several EUVD fields arrive as one string with embedded newlines."""
    if isinstance(value, list):
        return tuple(str(v).strip() for v in value if str(v).strip())
    if isinstance(value, str):
        return tuple(part.strip() for part in value.splitlines() if part.strip())
    return ()


def _names(value: Any, *keys: str) -> tuple[str, ...]:
    out: list[str] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                for key in keys:
                    nested = item.get(key)
                    if isinstance(nested, dict) and nested.get("name"):
                        out.append(str(nested["name"]))
                    elif isinstance(nested, str) and nested:
                        out.append(nested)
            elif isinstance(item, str) and item:
                out.append(item)
    return tuple(dict.fromkeys(out))


def _parse_record(doc: dict[str, Any], *, exploited: bool = False) -> EuvdRecord:
    aliases = _split_lines(doc.get("aliases"))
    cve = ""
    for alias in aliases:
        if alias.upper().startswith("CVE-"):
            cve = alias.upper()
            break

    score = doc.get("baseScore")
    epss = doc.get("epss")
    return EuvdRecord(
        id=str(doc.get("id", "") or ""),
        cve=cve,
        description=str(doc.get("description", "") or ""),
        published=str(doc.get("datePublished", "") or ""),
        updated=str(doc.get("dateUpdated", "") or ""),
        base_score=float(score) if isinstance(score, (int, float)) else None,
        base_score_version=str(doc.get("baseScoreVersion", "") or ""),
        base_score_vector=str(doc.get("baseScoreVector", "") or ""),
        epss=float(epss) if isinstance(epss, (int, float)) else None,
        aliases=aliases,
        references=_split_lines(doc.get("references")),
        vendors=_names(doc.get("enisaIdVendor"), "vendor"),
        products=_names(doc.get("enisaIdProduct"), "product"),
        exploited=exploited,
    )


class EuvdFeed(Feed):
    name = "euvd"
    host = "euvdservices.enisa.europa.eu"
    url = f"{API}/exploitedvulnerabilities"
    filename = "exploitedvulnerabilities.json"
    max_age = timedelta(hours=12)
    purpose = "ENISA's own exploited list and the EUVD id for the SRP form"
    terms = (
        "Published by ENISA. Reuse of EU institution material is generally "
        "permitted under Commission Decision 2011/833/EU with attribution; check "
        "the EUVD terms of use before redistributing."
    )

    def parse(self, raw: bytes) -> dict[str, EuvdRecord]:
        doc = json.loads(raw)
        items = doc.get("items", doc) if isinstance(doc, dict) else doc
        if not isinstance(items, list):
            return {}
        records: dict[str, EuvdRecord] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            record = _parse_record(item, exploited=True)
            key = record.cve or record.id
            if key:
                records[key.upper()] = record
        return records

    def exploited(self, cve: str) -> EuvdRecord | None:
        """Is this in ENISA's own exploited list?"""
        if not self.available():
            return None
        return self.load().get((cve or "").strip().upper())

    def lookup(self, identifier: str, *, allow_fetch: bool = True) -> EuvdRecord | None:
        """One record by EUVD id or CVE id."""
        identifier = (identifier or "").strip()
        if not identifier:
            return None
        name = f"enisaid/{identifier.upper()}.json"
        if self.cache.has(self.name, name):
            doc = self.cache.read_json(self.name, name)
        elif not allow_fetch:
            return None
        else:
            try:
                response = self.client.get(f"{API}/enisaid", params={"id": identifier})
            except FeedError as exc:
                log.info("EUVD lookup for %s failed: %s", identifier, exc)
                return None
            self.cache.write(
                self.name, name, response.body, url=f"{API}/enisaid?id={identifier}"
            )
            doc = response.json()
        if not isinstance(doc, dict) or not doc:
            return None
        return _parse_record(doc)

    def euvd_id(self, cve: str) -> str:
        record = self.lookup(cve, allow_fetch=False) or self.exploited(cve)
        return record.id if record else ""
