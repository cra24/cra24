# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""ENISA Single Reporting Platform dossier.

The platform went live on 11 September 2026 and shipped without an API, so every
submission is a human filling in a web form, in English, under a 24-hour clock.
This module therefore does not submit anything and never will. Its job is to have
the answer ready, in the platform's own field order, before the person opens the
browser at 2am — and to say plainly which answers are still missing, because the
expensive failure at that hour is discovering a blank mandatory field with four
hours left.

The field set lives in ``data/srp-fields.json``, not in this code. It is versioned
and carries its sources. When ENISA moves the form — and it will — the fix is a
data edit, and a user can patch it themselves without waiting for a release.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .. import DISCLAIMER, GENERATOR
from ..clock import Timeline, Track, timeline
from ..config import srp_spec, stage_fields, stage_spec
from ..model import Product
from ..triage import Triage

#: Values that mean "the operator has not answered this yet".
#:
#: ``"unknown"`` is in here deliberately: a field whose answer is the string
#: "unknown" has not been answered, whatever the form let you select.
_EMPTY: tuple[Any, ...] = (None, "", [], {}, "unknown")


@dataclass
class Dossier:
    """Everything needed to fill one SRP stage, plus what is still missing."""

    cve: str
    stage: str
    track: Track
    product: str
    generated_at: str
    fields: dict[str, Any] = field(default_factory=dict)
    gaps: list[str] = field(default_factory=list)
    soft_gaps: list[str] = field(default_factory=list)
    timeline: dict[str, Any] = field(default_factory=dict)
    triage: dict[str, Any] = field(default_factory=dict)
    spec_version: str = ""
    generator: str = GENERATOR
    disclaimer: str = DISCLAIMER

    @property
    def ready(self) -> bool:
        return not self.gaps

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "generated_by": self.generator,
            "disclaimer": self.disclaimer,
            "spec_version": self.spec_version,
            "cve": self.cve,
            "stage": self.stage,
            "track": self.track.value,
            "product": self.product,
            "ready_to_submit": self.ready,
            "srp_fields": self.fields,
            "blocking_gaps": self.gaps,
            "recommended_gaps": self.soft_gaps,
            "clocks": self.timeline,
            "triage": self.triage,
        }


def _derive(
    product: Product, result: Triage, cve: str, track: Track, stage: str, aware_at: str
) -> dict[str, Any]:
    """Everything cra24 can answer without asking the operator."""
    affected = result.affected
    carrier = affected[0] if affected else (result.components[0] if result.components else None)

    if carrier is not None:
        title = (
            f"{cve} in {carrier.component} {carrier.version} shipped in "
            f"{product.name} {product.version}"
        ).strip()
    else:
        title = f"{cve} affecting {product.name} {product.version}".strip()

    stage_label = {
        "early_warning": "Early warning",
        "notification": "Notification",
        "final_report": "Final report",
    }[stage]

    return {
        "notification_type": (
            "Actively exploited vulnerability"
            if track is Track.VULNERABILITY
            else "Severe incident"
        ),
        "notification_level": stage_label,
        "incident_title": title[:200],
        "manufacturer_name": product.manufacturer.name,
        "product_name": product.name,
        "product_version": product.version,
        "became_aware_at": aware_at,
        "affected_member_states": [m.upper() for m in product.member_states],
        "coordinator_csirt": product.manufacturer.coordinator_csirt,
        "product_category": product.machine or product.image or "",
        "annex_classification": product.annex_class,
        "component_name": carrier.component if carrier else "",
        "cve_id": cve if cve.upper().startswith("CVE-") else "",
        "euvd_id": cve if cve.upper().startswith("EUVD-") else "",
        "summary": result.summary,
    }


def build(
    product: Product,
    result: Triage,
    aware_at: str,
    *,
    stage: str = "early_warning",
    track: str | Track = Track.VULNERABILITY,
    answers: dict[str, Any] | None = None,
    measure_available_at: str | None = None,
    submitted: dict[str, str] | None = None,
) -> Dossier:
    """Assemble one stage's dossier.

    ``answers`` carries what only a human knows: the severity call, whether
    malicious intent is suspected, what corrective measure shipped. Anything it
    does not supply and cra24 cannot derive comes back as a gap.
    """
    track = Track(track) if isinstance(track, str) else track
    answers = {k: v for k, v in (answers or {}).items() if v not in ("", None)}
    spec = srp_spec()

    values = _derive(product, result, result.cve, track, stage, aware_at)
    values.update(answers)

    specs = stage_fields(stage)
    fields: dict[str, Any] = {}
    gaps: list[str] = []
    soft: list[str] = []

    for fs in specs:
        key = fs["key"]
        track_limit = fs.get("conditional_track")
        if track_limit and track_limit != values.get("notification_type"):
            continue
        value = values.get(key)
        fields[key] = value if value is not None else ""

        requirement = fs["requirement"]
        missing = value in _EMPTY
        if requirement == "required" and missing:
            gaps.append(f"{key} — {fs['label']}")
        elif requirement == "conditional" and missing:
            when = fs.get("required_when")
            if when and _condition_holds(when, values):
                gaps.append(f"{key} — {fs['label']} (required because {when})")
            else:
                soft.append(f"{key} — {fs['label']}")
        elif requirement == "derived" and missing:
            gaps.append(f"{key} — {fs['label']}")
        elif requirement == "optional" and missing:
            continue

    tl: Timeline = timeline(
        aware_at, track=track, measure_available_at=measure_available_at, submitted=submitted
    )

    return Dossier(
        cve=result.cve,
        stage=stage,
        track=track,
        product=product.name,
        generated_at=datetime.now(timezone.utc).isoformat(),
        fields=fields,
        gaps=gaps,
        soft_gaps=soft,
        timeline=tl.to_dict(),
        triage=result.to_dict(),
        spec_version=spec["spec_version"],
    )


def _condition_holds(expression: str, values: dict[str, Any]) -> bool:
    """Evaluate the tiny ``field == 'value'`` grammar used in the field spec.

    Deliberately not ``eval``. The spec file is data, and data from a file the
    user can edit never gets executed.
    """
    if "==" not in expression:
        return False
    left, _, right = expression.partition("==")
    return str(values.get(left.strip(), "")) == right.strip().strip("'\"")


def to_markdown(dossier: Dossier) -> str:
    """The version a human reads at 2am. Gaps first, because gaps are the news."""
    specs = {f["key"]: f for f in stage_fields(dossier.stage)}
    stage = stage_spec(dossier.stage)
    lines: list[str] = []

    lines.append(f"# CRA {stage['label'].lower()} draft — {dossier.cve}")
    lines.append("")
    lines.append(f"*{dossier.disclaimer}*")
    lines.append("")
    # The spec records both tracks' legal bases on one line; show only the one
    # that applies, because a dossier that cites the wrong article invites the
    # question of whether anything else in it was checked.
    basis = stage["legal_basis"]
    if ";" in basis:
        vuln_basis, _, incident_basis = basis.partition(";")
        basis = (vuln_basis if dossier.track is Track.VULNERABILITY else incident_basis).strip()
        basis = basis.split(" for ")[0].strip()
    lines.append(
        f"Product: **{dossier.fields.get('product_name', '')} "
        f"{dossier.fields.get('product_version', '')}** · "
        f"Track: {dossier.track} · Legal basis: {basis}"
    )
    lines.append("")

    # --- what is blocking you -------------------------------------------
    if dossier.gaps:
        lines.append(
            f"## Blocking — {len(dossier.gaps)} mandatory "
            f"field{'s' if len(dossier.gaps) != 1 else ''} unanswered"
        )
        lines.append("")
        lines.append(
            "You cannot submit until these have values. Nobody else can supply them for you."
        )
        lines.append("")
        for gap in dossier.gaps:
            lines.append(f"- [ ] {gap}")
        lines.append("")
    else:
        lines.append("## Ready")
        lines.append("")
        lines.append(
            "Every mandatory field for this stage has a value. Review them, then submit."
        )
        lines.append("")

    if dossier.soft_gaps:
        lines.append(
            "<details><summary>Recommended but not blocking "
            f"({len(dossier.soft_gaps)})</summary>"
        )
        lines.append("")
        for gap in dossier.soft_gaps:
            lines.append(f"- {gap}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    # --- clocks ----------------------------------------------------------
    lines += ["## Clocks", ""]
    lines += ["| Stage | Due | Remaining | State | Basis |", "| --- | --- | --- | --- | --- |"]
    for ob in dossier.timeline["obligations"]:
        due = ob["due_at"] or "not started"
        left = ob["remaining"] or "—"
        lines.append(f"| {ob['label']} | {due} | {left} | {ob['urgency']} | {ob['basis']} |")
    lines.append("")
    lines.append(
        "*The platform's own 72-hour counter has been reported to run from "
        "submission of the early warning rather than from the moment you became "
        "aware. The instants above are measured from awareness, which is the "
        "legal test.*"
    )
    lines.append("")

    # --- the fields, in the platform's order -----------------------------
    lines += [f"## Portal fields — {stage['label']}", ""]
    lines += ["| Field | Value | Required |", "| --- | --- | --- |"]
    for key, value in dossier.fields.items():
        fs = specs.get(key, {})
        if isinstance(value, list):
            shown = ", ".join(str(v) for v in value) if value else "**(fill in)**"
        else:
            shown = str(value).replace("\n", " ") if value not in _EMPTY else "**(fill in)**"
        if len(shown) > 300:
            shown = shown[:297] + "…"
        req = {
            "required": "yes",
            "conditional": "if applicable",
            "derived": "yes",
            "optional": "no",
        }.get(fs.get("requirement", ""), "")
        lines.append(f"| {fs.get('label', key)} | {shown} | {req} |")
    lines.append("")

    # --- the evidence ----------------------------------------------------
    triage = dossier.triage
    lines += ["## Affectedness", ""]
    if triage.get("components"):
        lines += [
            "| Component | Version | Status | Confidence | Justification |",
            "| --- | --- | --- | --- | --- |",
        ]
        for comp in triage["components"]:
            lines.append(
                f"| {comp['component']} | {comp['version']} | {comp['status']} | "
                f"{comp['confidence']} | {comp['justification'] or '—'} |"
            )
        lines.append("")
        lines.append("<details><summary>Why — the rules that fired</summary>")
        lines.append("")
        for comp in triage["components"]:
            lines.append(f"**{comp['component']} {comp['version']}**")
            lines.append("")
            for finding in comp["findings"]:
                src = f" *(source: {finding['source']})*" if finding["source"] else ""
                lines.append(
                    f"- `{finding['rule']}` → {finding['conclusion']}"
                    f"{': ' + finding['evidence'] if finding['evidence'] else ''}{src}"
                )
            lines.append("")
        lines.append("</details>")
        lines.append("")
    else:
        lines.append("No component in this image carries this identifier.")
        lines.append("")

    lines += ["## Assessment", "", triage.get("summary", ""), ""]
    if triage.get("reportable_reason"):
        verdict = "**Reportable**" if triage.get("reportable") else "**Not reportable**"
        lines.append(f"{verdict} — {triage['reportable_reason']}")
        lines.append("")
    if triage.get("requires_human"):
        lines.append(
            "> A human decision is still required on at least one component. "
            "Search for `requires_human` in the JSON dossier to find which."
        )
        lines.append("")

    lines += [
        "---",
        "",
        f"Generated {dossier.generated_at} by {dossier.generator}. "
        f"Field spec version {dossier.spec_version}.",
        "",
    ]
    return "\n".join(lines)


# Backwards-compatible names from 0.1.
def early_warning(product: Product, cve: str, aware_at: str, **kwargs: Any) -> dict[str, Any]:
    from ..triage import triage as run_triage

    result = run_triage(product, cve)
    return build(product, result, aware_at, **kwargs).to_dict()


def early_warning_markdown(dossier: dict[str, Any]) -> str:  # pragma: no cover - shim
    raise NotImplementedError(
        "the 0.1 dict-based markdown shim was removed; use emit.srp.to_markdown(Dossier)"
    )
