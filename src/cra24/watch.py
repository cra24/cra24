# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Watch mode: poll the feeds against registered products and fire when something lands.

What makes this worth running, stated plainly: the thing waiting in your inbox at
07:00 is not an alert. It is a **dossier with four fields left to fill and a
clock that started at 03:14**, which is the difference between discovering an
obligation and being halfway through discharging it.

Three properties that make it usable rather than merely functional:

**An alert fires once.** State is persisted per product and CVE. A watcher that
re-sends the same finding every fifteen minutes trains its readers to filter it,
and then the one that mattered is filtered too. A *new* alert is sent only when
the verdict changes in a direction that matters — not affected to affected, or
not reportable to reportable.

**The clock starts at detection, and never moves afterwards.** ``became_aware_at``
is written the first time the product is seen to be affected, and is never
rewritten. Article 14 runs from awareness; a tool that quietly refreshed that
timestamp on every poll would produce a dossier that understates how long you
have known, which is the one error here with legal consequences.

**A failure on one product does not stop the rest.** A malformed product file, an
unreachable feed, a webhook that is down: logged, recorded, move on.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .clock import timeline
from .errors import ConfigError
from .feeds.registry import FeedSet, best_component
from .logging import get
from .model import BuildStatus, Product
from .notify import Alert
from .triage import VexStatus, triage

log = get("watch")

STATE_FILE = "watch-state.json"


@dataclass
class Tracked:
    """What we already know about one product and CVE pair."""

    product: str
    cve: str
    first_seen: str = ""
    became_aware_at: str = ""
    last_status: str = ""
    last_reportable: bool = False
    notified_at: str = ""
    notify_count: int = 0
    dossier_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "cve": self.cve,
            "first_seen": self.first_seen,
            "became_aware_at": self.became_aware_at,
            "last_status": self.last_status,
            "last_reportable": self.last_reportable,
            "notified_at": self.notified_at,
            "notify_count": self.notify_count,
            "dossier_path": self.dossier_path,
        }


class State:
    """Persisted watch state. Plain JSON, because it has to be readable by a human
    at 3am and editable when the tool has got something wrong."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.entries: dict[str, Tracked] = {}
        self.load()

    @staticmethod
    def key(product: str, cve: str) -> str:
        return f"{product}::{cve.upper()}"

    def load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise ConfigError(
                f"{self.path} is not readable as watch state: {exc}",
                hint="delete it to start fresh — you will get one repeat alert "
                "per open finding, which is better than losing the clocks",
            ) from exc
        known = set(Tracked.__dataclass_fields__)
        for key, entry in (data.get("entries") or {}).items():
            self.entries[key] = Tracked(**{k: v for k, v in entry.items() if k in known})

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "tool_version": __version__,
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "entries": {k: v.to_dict() for k, v in sorted(self.entries.items())},
        }
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    def get(self, product: str, cve: str) -> Tracked | None:
        return self.entries.get(self.key(product, cve))

    def put(self, entry: Tracked) -> None:
        self.entries[self.key(entry.product, entry.cve)] = entry

    def open_findings(self) -> list[Tracked]:
        return [e for e in self.entries.values() if e.last_reportable]


@dataclass
class WatchResult:
    checked_products: int = 0
    checked_cves: int = 0
    alerts: list[Alert] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_unchanged: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked_products": self.checked_products,
            "checked_cves": self.checked_cves,
            "alerts": [a.to_dict() for a in self.alerts],
            "new_alerts": len(self.alerts),
            "skipped_unchanged": self.skipped_unchanged,
            "errors": self.errors,
        }


def load_products(source: str | Path) -> list[tuple[Path, Product]]:
    """Load one ``product.json`` or every one in a directory."""
    p = Path(source)
    paths = sorted(p.glob("*.json")) if p.is_dir() else [p]
    out: list[tuple[Path, Product]] = []
    for path in paths:
        if path.name == STATE_FILE:
            continue
        try:
            out.append((path, Product.load(path)))
        except ConfigError as exc:
            log.error("skipping %s: %s", path, exc.message)
    if not out:
        raise ConfigError(
            f"no product files found at {p}",
            hint="run `cra24 scan --out products/gateway.json` for each device family",
        )
    return out


def candidate_cves(product: Product, *, include_all: bool = False) -> list[str]:
    """Which CVEs are worth asking the feeds about.

    By default only the ones the build reports as unpatched or unknown. A CVE the
    layer patched does not become reportable because CISA added it to KEV — you
    are not affected by it — and asking about all of them turns a two-second
    check into a thousand-request crawl.
    """
    out: list[str] = []
    for component in product.components:
        for record in component.cves.values():
            if include_all or record.status in (BuildStatus.UNPATCHED, BuildStatus.UNKNOWN):
                out.append(record.id)
    return sorted(set(out))


def _write_dossier(
    product: Product, result: Any, aware_at: str, out_root: Path
) -> tuple[str, list[str]]:
    """Write the early-warning dossier for an alert. Returns (path, gaps)."""
    from .emit import csaf as csaf_mod
    from .emit import srp as srp_mod
    from .emit import validate as validate_mod
    from .emit import vex as vex_mod
    from .evidence import Ledger

    slug = result.cve.lower()
    outdir = out_root / slug
    outdir.mkdir(parents=True, exist_ok=True)

    dossier = srp_mod.build(product, result, aware_at, stage="early_warning")
    written: list[Path] = []

    path = outdir / f"{slug}-early-warning.json"
    path.write_text(
        json.dumps(dossier.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    written.append(path)

    markdown = outdir / f"{slug}-early-warning.md"
    markdown.write_text(srp_mod.to_markdown(dossier), encoding="utf-8")
    written.append(markdown)

    advisory = csaf_mod.build(product, result, csaf_mod.tracking_id(product, result.cve))
    vex_doc = vex_mod.build(product, result, vex_mod.document_id(product, result.cve))
    try:
        validate_mod.validate_csaf(advisory)
        validate_mod.validate_openvex(vex_doc)
    except Exception as exc:
        log.error("generated documents for %s did not validate: %s", result.cve, exc)

    for name, doc in ((f"{slug}.csaf.json", advisory), (f"{slug}.openvex.json", vex_doc)):
        path = outdir / name
        path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(path)

    Ledger(out_root / "evidence").append(
        "watch-detection",
        written,
        meta={
            "cve": result.cve,
            "product": product.name,
            "product_version": product.version,
            "aware_at": aware_at,
            "detected_by": "cra24 watch",
            "tool_version": __version__,
            "triage_status": result.status.value,
        },
    )
    return str(markdown), dossier.gaps


def run_once(
    products: str | Path,
    *,
    feeds: FeedSet | None = None,
    state_path: str | Path | None = None,
    dossier_root: str | Path = "watch-dossiers",
    include_all_cves: bool = False,
    write_dossiers: bool = True,
    now: datetime | None = None,
) -> WatchResult:
    """One pass over every registered product."""
    feeds = feeds or FeedSet()
    loaded = load_products(products)
    root = Path(products)
    state = State(state_path or (root if root.is_dir() else root.parent) / STATE_FILE)
    result = WatchResult()
    stamp = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")

    for path, product in loaded:
        result.checked_products += 1
        label = product.name or path.stem
        for cve in candidate_cves(product, include_all=include_all_cves):
            result.checked_cves += 1
            try:
                component = best_component(product, cve)
                enrichment = feeds.enrich(cve, component)
                verdict = triage(product, cve, enrichment=enrichment)
            except Exception as exc:
                message = f"{label}/{cve}: {exc}"
                log.error("%s", message)
                result.errors.append(message)
                continue

            tracked = state.get(label, cve) or Tracked(product=label, cve=cve, first_seen=stamp)

            newly_affected = verdict.status is VexStatus.AFFECTED
            escalated = verdict.reportable and not tracked.last_reportable
            first_time = newly_affected and not tracked.last_status
            changed = verdict.status.value != tracked.last_status

            if newly_affected and not tracked.became_aware_at:
                # The clock starts here and is never rewritten.
                tracked.became_aware_at = stamp

            should_alert = (
                escalated or (first_time and newly_affected) or (changed and newly_affected)
            )

            tracked.last_status = verdict.status.value
            tracked.last_reportable = verdict.reportable

            if not should_alert:
                result.skipped_unchanged += 1
                state.put(tracked)
                continue

            aware_at = tracked.became_aware_at or stamp
            dossier_path: str = ""
            gaps: list[str] = []
            if write_dossiers:
                try:
                    dossier_path, gaps = _write_dossier(
                        product, verdict, aware_at, Path(dossier_root) / _slug(label)
                    )
                except Exception as exc:
                    message = f"{label}/{cve}: could not write dossier: {exc}"
                    log.error("%s", message)
                    result.errors.append(message)

            tl = timeline(aware_at)
            early = tl["early_warning"]
            alert = Alert(
                product=label,
                product_version=product.version,
                cve=cve,
                status=verdict.status.value,
                reportable=verdict.reportable,
                summary=verdict.summary,
                detected_at=aware_at,
                early_warning_due=early.due_at.isoformat() if early.due_at else "",
                remaining=early.to_dict()["remaining"] or "",
                dossier_path=dossier_path,
                gaps=gaps,
                severity=enrichment.severity,
                epss=enrichment.epss,
                ransomware=enrichment.ransomware,
                components=[c.component for c in verdict.affected],
            )
            result.alerts.append(alert)
            tracked.notified_at = stamp
            tracked.notify_count += 1
            tracked.dossier_path = dossier_path
            state.put(tracked)

    state.save()
    return result


def _slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in value).strip("-").lower()
