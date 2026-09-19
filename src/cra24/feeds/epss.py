# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""EPSS — Exploit Prediction Scoring System.

EPSS estimates the probability that a vulnerability will be exploited in the
next 30 days. It is for **ordering your queue**, not for deciding what to report.

That line is worth holding. EPSS is a prediction; Article 14(1) turns on an
observed fact. A 0.97 EPSS score is a reason to look at something first thing
tomorrow; it is not evidence of active exploitation and cra24 will never treat it
as such. The feed exists here so that a maintainer with forty unpatched CVEs
knows which three to open first.

The bulk CSV is one request for every CVE scored, which is the right shape for a
build machine. The per-CVE API exists for interactive use.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from datetime import timedelta

from ..logging import get
from .base import Feed

log = get("feeds.epss")

BULK_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
API_URL = "https://api.first.org/data/v1/epss"


@dataclass(frozen=True)
class EpssScore:
    cve: str
    probability: float
    percentile: float
    date: str = ""

    @property
    def band(self) -> str:
        """A word a human can act on, rather than four decimal places."""
        if self.probability >= 0.5:
            return "very high"
        if self.probability >= 0.1:
            return "high"
        if self.probability >= 0.01:
            return "moderate"
        return "low"

    def summary(self) -> str:
        return (
            f"EPSS {self.probability:.4f} ({self.band}), "
            f"{self.percentile:.1%} percentile" + (f", scored {self.date}" if self.date else "")
        )


class EpssFeed(Feed):
    name = "epss"
    host = "epss.cyentia.com"
    url = BULK_URL
    filename = "epss_scores-current.csv"
    max_age = timedelta(hours=24)
    purpose = "how likely is exploitation in the next 30 days (for ordering, not reporting)"
    terms = (
        "EPSS data is provided by FIRST.org under the terms on first.org/epss. "
        "Free for any use including commercial, with attribution to FIRST."
    )

    def parse(self, raw: bytes) -> dict[str, EpssScore]:
        text = raw.decode("utf-8", errors="replace")
        scores: dict[str, EpssScore] = {}
        # The bulk file starts with a comment line carrying the model version and
        # score date, before the CSV header.
        date = ""
        lines = []
        for line in text.splitlines():
            if line.startswith("#"):
                for token in line.lstrip("#").split(","):
                    key, _, value = token.partition(":")
                    if key.strip() == "score_date":
                        date = value.strip()[:10]
                continue
            lines.append(line)

        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        for row in reader:
            cve = (row.get("cve") or "").strip().upper()
            if not cve:
                continue
            try:
                scores[cve] = EpssScore(
                    cve=cve,
                    probability=float(row.get("epss") or 0.0),
                    percentile=float(row.get("percentile") or 0.0),
                    date=date,
                )
            except ValueError:
                log.debug("skipping unparseable EPSS row for %s", cve)
        return scores

    def lookup(self, cve: str) -> EpssScore | None:
        return self.load().get((cve or "").strip().upper())
