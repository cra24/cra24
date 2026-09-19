# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""NVD — CVSS scores, CWE and references.

NVD is used here for one thing: a defensible severity figure to put in the
72-hour notification and the final report, with the vector string so a reader can
check the reasoning rather than take the number on trust.

It is deliberately **not** used for affectedness. NVD's CPE configurations are
notoriously coarse for embedded components — a CPE for "linux_kernel" matches
every kernel ever shipped — and treating that as "you are affected" is how a
triage tool produces five hundred findings for one image. OSV's version ranges
answer that question properly.

Rate limits are real: roughly 5 requests per rolling 30 seconds without an API
key, 50 with one. The client spaces requests accordingly. Set ``NVD_API_KEY`` to
get the faster budget; keys are free from nvd.nist.gov.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from ..logging import get
from .base import Feed, FeedError, HttpClient

log = get("feeds.nvd")

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEY_ENV = "NVD_API_KEY"

#: Seconds between requests. NVD publishes 5 per 30s unkeyed, 50 per 30s keyed;
#: these are deliberately a little slower than the stated ceiling, because being
#: rate-limited mid-incident is worse than being slow.
INTERVAL_UNKEYED = 6.5
INTERVAL_KEYED = 0.7


@dataclass(frozen=True)
class NvdRecord:
    cve: str
    published: str = ""
    last_modified: str = ""
    status: str = ""
    description: str = ""
    cvss_version: str = ""
    cvss_vector: str = ""
    base_score: float | None = None
    base_severity: str = ""
    cwes: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    def severity_word(self) -> str:
        """Lower-cased severity, matching the SRP's own vocabulary."""
        return (self.base_severity or "").strip().lower() or "unknown"

    def summary(self) -> str:
        if self.base_score is None:
            return f"{self.cve}: no CVSS score published"
        return (
            f"CVSS {self.cvss_version} {self.base_score} "
            f"({self.severity_word()}), {self.cvss_vector}"
        )

    def cvss_object(self) -> dict[str, Any] | None:
        """A CSAF-shaped CVSS v3.1 block, or None when the version is not 3.1."""
        if not self.cvss_vector or not self.base_score or self.cvss_version != "3.1":
            return None
        return {
            "version": "3.1",
            "vectorString": self.cvss_vector,
            "baseScore": self.base_score,
            "baseSeverity": (self.base_severity or "").upper(),
        }


def _pick_metric(metrics: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """Prefer the newest CVSS version NVD published, and a primary source."""
    for version, key in (
        ("4.0", "cvssMetricV40"),
        ("3.1", "cvssMetricV31"),
        ("3.0", "cvssMetricV30"),
        ("2.0", "cvssMetricV2"),
    ):
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        return version, primary
    return None


def _parse_record(item: dict[str, Any]) -> NvdRecord:
    cve = item.get("cve", item)
    description = ""
    for entry in cve.get("descriptions", []) or []:
        if entry.get("lang") == "en":
            description = entry.get("value", "")
            break

    version = vector = severity = ""
    score: float | None = None
    picked = _pick_metric(cve.get("metrics", {}) or {})
    if picked:
        version, metric = picked
        data = metric.get("cvssData", {}) or {}
        vector = data.get("vectorString", "")
        severity = data.get("baseSeverity", "")
        raw_score = data.get("baseScore")
        score = float(raw_score) if raw_score is not None else None

    cwes = []
    for weakness in cve.get("weaknesses", []) or []:
        for entry in weakness.get("description", []) or []:
            value = entry.get("value", "")
            if value.startswith("CWE-"):
                cwes.append(value)

    references = [r.get("url", "") for r in (cve.get("references", []) or []) if r.get("url")]

    return NvdRecord(
        cve=(cve.get("id") or "").upper(),
        published=cve.get("published", ""),
        last_modified=cve.get("lastModified", ""),
        status=cve.get("vulnStatus", ""),
        description=description,
        cvss_version=version,
        cvss_vector=vector,
        base_score=score,
        base_severity=severity,
        cwes=tuple(dict.fromkeys(cwes)),
        references=tuple(references[:10]),
    )


class NvdFeed(Feed):
    name = "nvd"
    host = "services.nvd.nist.gov"
    url = API
    filename = "index.json"  # unused; NVD is queried per CVE
    max_age = timedelta(days=7)
    purpose = "CVSS severity and vector for the notification and final report"
    terms = (
        "NVD data is a US Government work, generally free of copyright in the "
        "United States. NVD asks that you do not imply endorsement by NIST."
    )

    def __init__(self, cache=None, client: HttpClient | None = None) -> None:
        if client is None:
            keyed = bool(os.environ.get(KEY_ENV, "").strip())
            client = HttpClient(min_interval=INTERVAL_KEYED if keyed else INTERVAL_UNKEYED)
        super().__init__(cache, client)

    def parse(self, raw: bytes) -> Any:
        return json.loads(raw)

    def lookup(self, cve: str, *, allow_fetch: bool = True) -> NvdRecord | None:
        cve = (cve or "").strip().upper()
        if not cve.startswith("CVE-"):
            return None
        name = f"cves/{cve}.json"
        if self.cache.has(self.name, name):
            doc = self.cache.read_json(self.name, name)
        elif not allow_fetch:
            return None
        else:
            headers = {}
            api_key = os.environ.get(KEY_ENV, "").strip()
            if api_key:
                headers["apiKey"] = api_key
            try:
                response = self.client.get(API, params={"cveId": cve}, headers=headers)
            except FeedError as exc:
                log.info("NVD lookup for %s failed: %s", cve, exc)
                return None
            self.cache.write(self.name, name, response.body, url=f"{API}?cveId={cve}")
            doc = response.json()

        items = doc.get("vulnerabilities", []) or []
        if not items:
            return None
        return _parse_record(items[0])

    def status(self):  # type: ignore[override]
        from .base import FeedStatus

        root = self.cache.root / self.name / "cves"
        count = len(list(root.glob("*.json"))) if root.is_dir() else 0
        keyed = bool(os.environ.get(KEY_ENV, "").strip())
        return FeedStatus(
            name=self.name,
            host=self.host,
            present=count > 0,
            fetched_at="",
            age_hours=None,
            fresh=count > 0,
            records=count,
            note=self.purpose
            + (
                f" ({KEY_ENV} set, 50 req/30s)"
                if keyed
                else f" (no {KEY_ENV}, limited to 5 req/30s)"
            ),
        )
