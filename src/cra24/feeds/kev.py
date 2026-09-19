# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""CISA Known Exploited Vulnerabilities.

**Why this feed matters more than any other here.** Article 14(1) obliges a
manufacturer to report an *actively exploited* vulnerability. Not a severe one, a
critical one, or an unpatched one — an exploited one. KEV is the closest thing to
a public, authoritative, machine-readable answer to "is this being exploited".

**Why it is a proxy and not the answer.** KEV is a US federal remediation
mandate, not an EU legal instrument. It is conservative by design: CISA adds an
entry when it has confirmed exploitation, so presence is strong evidence and
absence is weak evidence. A vulnerability being exploited against your specific
product, reported to you by a customer, triggers Article 14 whether or not CISA
has heard of it.

cra24 therefore treats KEV as ``actively_exploited=True`` when present, and
leaves the value **unknown** when absent rather than asserting ``False``. The
distinction is the whole reason this file has a docstring this long.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from ..logging import get
from .base import Feed

log = get("feeds.kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass(frozen=True)
class KevEntry:
    cve: str
    vendor_project: str = ""
    product: str = ""
    name: str = ""
    date_added: str = ""
    short_description: str = ""
    required_action: str = ""
    due_date: str = ""
    known_ransomware: str = ""
    notes: str = ""
    cwes: tuple[str, ...] = ()

    @property
    def ransomware(self) -> bool:
        return self.known_ransomware.strip().lower() == "known"

    def summary(self) -> str:
        bits = (
            [f"listed in CISA KEV on {self.date_added}"]
            if self.date_added
            else ["listed in CISA KEV"]
        )
        if self.vendor_project or self.product:
            bits.append(f"as {self.vendor_project} {self.product}".strip())
        if self.ransomware:
            bits.append("known use in ransomware campaigns")
        return "; ".join(bits)


class KevFeed(Feed):
    name = "kev"
    host = "www.cisa.gov"
    url = KEV_URL
    filename = "known_exploited_vulnerabilities.json"
    # CISA adds entries when exploitation is confirmed rather than on a schedule,
    # so a day-old copy can be a day late. Six hours is a reasonable compromise
    # for a ~500KB file.
    max_age = timedelta(hours=6)
    purpose = "is this vulnerability being actively exploited (Article 14(1) trigger)"
    terms = (
        "Published by CISA as a US Government work, generally free of copyright in "
        "the United States. Check current terms before redistributing a copy."
    )

    def parse(self, raw: bytes) -> dict[str, KevEntry]:
        import json

        doc = json.loads(raw)
        entries: dict[str, KevEntry] = {}
        for item in doc.get("vulnerabilities", []) or []:
            cve = (item.get("cveID") or "").strip().upper()
            if not cve:
                continue
            entries[cve] = KevEntry(
                cve=cve,
                vendor_project=item.get("vendorProject", ""),
                product=item.get("product", ""),
                name=item.get("vulnerabilityName", ""),
                date_added=item.get("dateAdded", ""),
                short_description=item.get("shortDescription", ""),
                required_action=item.get("requiredAction", ""),
                due_date=item.get("dueDate", ""),
                known_ransomware=item.get("knownRansomwareCampaignUse", ""),
                notes=item.get("notes", ""),
                cwes=tuple(item.get("cwes", []) or []),
            )
        return entries

    def catalog_version(self) -> str:
        import json

        if not self.available():
            return ""
        try:
            return json.loads(self.cache.read_bytes(self.name, self.filename)).get(
                "catalogVersion", ""
            )
        except Exception:
            return ""

    def lookup(self, cve: str) -> KevEntry | None:
        return self.load().get((cve or "").strip().upper())

    def contains(self, cve: str) -> bool:
        return self.lookup(cve) is not None
