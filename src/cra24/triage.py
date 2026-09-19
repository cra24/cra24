# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Affectedness triage: from "the scanner says CVE-X" to a defensible VEX status.

This is the module that earns the project its keep. Everyone can generate an
SBOM. The unserved job is the one after it: given a CVE, is it actually in my
shipped image, in a code path that runs, and what do I say about it in public.

Design rules, learned from watching this go wrong:

* **Every conclusion carries its evidence.** A ``Triage`` is never just a status;
  it is a status plus the ordered list of findings that produced it plus the file
  each finding came from. In ten years the evidence is the only part anyone cares
  about, and it is the part every other tool discards.
* **The tool never silently upgrades confidence.** ``patched`` in Yocto metadata
  means a layer applied *a* patch, not that you are safe. That yields a ``fixed``
  status with ``requires_human`` set, not a quiet all-clear.
* **Justifications come from the closed OpenVEX vocabulary**, never free text,
  because a free-text justification is one a downstream scanner cannot act on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from .model import BuildStatus, Component, CveRecord, Product
from .versions import compare, in_range

if TYPE_CHECKING:  # pragma: no cover
    from .feeds.registry import Enrichment


class VexStatus(str, Enum):
    """The four OpenVEX status labels. There are no others."""

    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"

    def __str__(self) -> str:
        return self.value


class Justification(str, Enum):
    """The five OpenVEX justification labels, valid only with ``not_affected``."""

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = (
        "vulnerable_code_cannot_be_controlled_by_adversary"
    )
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"

    def __str__(self) -> str:
        return self.value


#: CSAF product_status branch for each VEX status.
CSAF_STATUS = {
    VexStatus.NOT_AFFECTED: "known_not_affected",
    VexStatus.AFFECTED: "known_affected",
    VexStatus.FIXED: "fixed",
    VexStatus.UNDER_INVESTIGATION: "under_investigation",
}

#: CSAF flag labels, which are the CSAF spelling of the OpenVEX justifications.
CSAF_FLAG = {
    Justification.COMPONENT_NOT_PRESENT: "component_not_present",
    Justification.VULNERABLE_CODE_NOT_PRESENT: "vulnerable_code_not_present",
    Justification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH: "vulnerable_code_not_in_execute_path",
    Justification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY: "vulnerable_code_cannot_be_controlled_by_adversary",
    Justification.INLINE_MITIGATIONS_ALREADY_EXIST: "inline_mitigations_already_exist",
}

#: Yocto ``CVE_STATUS`` reason strings mapped to a VEX reading.
#:
#: Yocto groups these into patched / ignored / unpatched through
#: ``CVE_CHECK_STATUSMAP``. The group tells you what cve-check printed; the reason
#: string tells you *why*, and only the reason string maps to a defensible VEX
#: justification. This table is the translation, and it is where most of the
#: false-positive reduction actually lives.
YOCTO_REASON_MAP: dict[str, tuple[VexStatus, Justification | None, bool]] = {
    # reason: (status, justification, requires_human)
    "patched": (VexStatus.FIXED, None, False),
    "backported-patch": (VexStatus.FIXED, None, False),
    "cpe-stable-backport": (VexStatus.FIXED, None, False),
    "fixed-version": (VexStatus.FIXED, None, False),
    "not-applicable-config": (
        VexStatus.NOT_AFFECTED,
        Justification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        False,
    ),
    "not-applicable-platform": (
        VexStatus.NOT_AFFECTED,
        Justification.VULNERABLE_CODE_NOT_PRESENT,
        False,
    ),
    "not-applicable-os": (
        VexStatus.NOT_AFFECTED,
        Justification.VULNERABLE_CODE_NOT_PRESENT,
        False,
    ),
    "cpe-incorrect": (VexStatus.NOT_AFFECTED, Justification.COMPONENT_NOT_PRESENT, True),
    "disputed": (VexStatus.UNDER_INVESTIGATION, None, True),
    "upstream-wontfix": (VexStatus.AFFECTED, None, True),
    "ignored": (VexStatus.NOT_AFFECTED, None, True),
    "unpatched": (VexStatus.AFFECTED, None, False),
    "vulnerable-investigating": (VexStatus.UNDER_INVESTIGATION, None, True),
}

#: CycloneDX ``analysis.justification`` values mapped the same way.
#:
#: CycloneDX has its own nine-value vocabulary, OpenVEX has five, and they do not
#: line up one to one. Where CycloneDX is more specific (``requires_dependency``
#: versus ``requires_environment``) the distinction is preserved in the finding's
#: evidence text rather than lost, even though both collapse to the same OpenVEX
#: label.
CYCLONEDX_REASON_MAP: dict[str, tuple[VexStatus, Justification | None, bool]] = {
    "code-not-present": (
        VexStatus.NOT_AFFECTED,
        Justification.VULNERABLE_CODE_NOT_PRESENT,
        False,
    ),
    "code-not-reachable": (
        VexStatus.NOT_AFFECTED,
        Justification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        False,
    ),
    "requires-configuration": (
        VexStatus.NOT_AFFECTED,
        Justification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        False,
    ),
    "requires-dependency": (
        VexStatus.NOT_AFFECTED,
        Justification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        False,
    ),
    "requires-environment": (
        VexStatus.NOT_AFFECTED,
        Justification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
        False,
    ),
    "protected-by-compiler": (
        VexStatus.NOT_AFFECTED,
        Justification.INLINE_MITIGATIONS_ALREADY_EXIST,
        False,
    ),
    "protected-at-runtime": (
        VexStatus.NOT_AFFECTED,
        Justification.INLINE_MITIGATIONS_ALREADY_EXIST,
        False,
    ),
    "protected-at-perimeter": (
        VexStatus.NOT_AFFECTED,
        Justification.INLINE_MITIGATIONS_ALREADY_EXIST,
        False,
    ),
    "protected-by-mitigating-control": (
        VexStatus.NOT_AFFECTED,
        Justification.INLINE_MITIGATIONS_ALREADY_EXIST,
        False,
    ),
}

#: Every reason string cra24 understands, whatever produced it.
REASON_MAP: dict[str, tuple[VexStatus, Justification | None, bool]] = {
    **YOCTO_REASON_MAP,
    **CYCLONEDX_REASON_MAP,
}


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    def __str__(self) -> str:
        return self.value


@dataclass
class Finding:
    """One rule that fired, and the evidence it fired on."""

    rule: str
    conclusion: str
    evidence: str = ""
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "conclusion": self.conclusion,
            "evidence": self.evidence,
            "source": self.source,
        }


@dataclass
class ComponentTriage:
    """The verdict for one component."""

    component: str
    version: str
    purl: str
    status: VexStatus
    justification: Justification | None = None
    impact_statement: str = ""
    action_statement: str = ""
    confidence: Confidence = Confidence.MEDIUM
    requires_human: bool = False
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "component": self.component,
            "version": self.version,
            "purl": self.purl,
            "status": self.status.value,
            "justification": self.justification.value if self.justification else None,
            "impact_statement": self.impact_statement,
            "action_statement": self.action_statement,
            "confidence": self.confidence.value,
            "requires_human": self.requires_human,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Triage:
    """The verdict for a product, aggregated over its components."""

    cve: str
    product: str
    status: VexStatus
    components: list[ComponentTriage] = field(default_factory=list)
    requires_human: bool = False
    summary: str = ""
    reportable: bool = False
    reportable_reason: str = ""
    #: What the feeds contributed, if any were consulted. Kept alongside the
    #: verdict so a dossier can show that a status changed because CISA added
    #: the CVE to KEV this morning, rather than because the tool changed its mind.
    enrichment: dict[str, Any] = field(default_factory=dict)

    @property
    def affected(self) -> list[ComponentTriage]:
        return [c for c in self.components if c.status is VexStatus.AFFECTED]

    def to_dict(self) -> dict:
        return {
            "cve": self.cve,
            "product": self.product,
            "status": self.status.value,
            "requires_human": self.requires_human,
            "summary": self.summary,
            "reportable": self.reportable,
            "reportable_reason": self.reportable_reason,
            "enrichment": self.enrichment,
            "components": [c.to_dict() for c in self.components],
        }


def _reason_of(record: CveRecord) -> str:
    """Pull the Yocto CVE_STATUS reason out of a record's detail string."""
    detail = (record.detail or "").strip().lower()
    if not detail:
        return ""
    # cve-check writes the reason as the first token, sometimes followed by a
    # colon and a human justification.
    head = detail.split(":", 1)[0].strip()
    head = head.replace("_", "-").replace(" ", "-")
    return head if head in REASON_MAP else ""


def _config_gate(
    product: Product, component: Component, gate_symbols: list[str] | None = None
) -> tuple[bool, str] | None:
    """Is the vulnerable code compiled out of the kernel we actually ship?

    Returns ``(gated_out, evidence)`` when a conclusion can be drawn, ``None``
    when there is no information. Absence of gating data must never be read as
    "not gated": that is the mistake that turns a triage tool into a liability.

    ``gate_symbols`` are the symbols an advisory says gate *this CVE*, which is
    the useful granularity — a kernel has thousands of CVEs and each one is
    reachable only under its own subsystem's config. They take precedence over
    the component's own symbols.
    """
    symbols = gate_symbols or component.config_symbols
    if not symbols or not product.kernel_config:
        return None
    enabled = []
    disabled = []
    unknown = []
    for sym in symbols:
        value = product.kernel_config.get(sym)
        if value in ("y", "m"):
            enabled.append(f"{sym}={value}")
        elif value in ("n", ""):
            # kconfig wrote "# CONFIG_FOO is not set": we looked, it is off.
            disabled.append(sym)
        elif product.kernel_config_complete:
            # Absent from a generated .config. Every reachable symbol was
            # considered when that file was written, so absence is an answer.
            disabled.append(sym)
        else:
            # Absent from a defconfig or fragment, which lists only deltas.
            # This is "we never looked", and it is not evidence of anything.
            unknown.append(sym)

    if enabled:
        return False, "enabled in the shipped kernel config: " + ", ".join(sorted(enabled))
    if unknown:
        # Refusing to answer is the whole point. Treating these as disabled
        # would gate a live vulnerability out of the dossier on the strength of
        # a config file that never mentioned it.
        return None
    if disabled:
        return True, "not set in the shipped kernel config: " + ", ".join(sorted(disabled))
    return None


def triage_component(
    product: Product,
    component: Component,
    cve: str,
    *,
    advisory_fixed_version: str | None = None,
    advisory_introduced: str | None = None,
    advisory_last_affected: str | None = None,
    gate_symbols: list[str] | None = None,
) -> ComponentTriage:
    """Decide one component's status for one CVE, recording why."""
    cve = cve.strip().upper()
    record = component.record(cve)
    findings: list[Finding] = []
    result = ComponentTriage(
        component=component.name,
        version=component.version,
        purl=component.identifier(),
        status=VexStatus.UNDER_INVESTIGATION,
    )

    # Rule 1 - advisory version range. The most authoritative signal when present,
    # because it comes from the people who fixed the bug.
    if advisory_fixed_version or advisory_introduced or advisory_last_affected:
        inside = in_range(
            component.version,
            introduced=advisory_introduced,
            fixed=advisory_fixed_version,
            last_affected=advisory_last_affected,
        )
        bounds = ", ".join(
            filter(
                None,
                [
                    f"introduced {advisory_introduced}" if advisory_introduced else "",
                    f"fixed {advisory_fixed_version}" if advisory_fixed_version else "",
                    f"last affected {advisory_last_affected}" if advisory_last_affected else "",
                ],
            )
        )
        if not inside:
            ahead = (
                advisory_fixed_version
                and compare(component.version, advisory_fixed_version) >= 0
            )
            findings.append(
                Finding(
                    rule="advisory-version-range",
                    conclusion="fixed" if ahead else "outside the affected range",
                    evidence=f"{component.name} {component.version} is outside [{bounds}]",
                    source="advisory",
                )
            )
            result.status = VexStatus.FIXED if ahead else VexStatus.NOT_AFFECTED
            if not ahead:
                result.justification = Justification.VULNERABLE_CODE_NOT_PRESENT
            result.confidence = Confidence.HIGH
            result.findings = findings
            return result
        findings.append(
            Finding(
                rule="advisory-version-range",
                conclusion="within the affected range",
                evidence=f"{component.name} {component.version} is inside [{bounds}]",
                source="advisory",
            )
        )

    # Rule 2 - the build system's own CVE_STATUS reason.
    if record is not None:
        reason = _reason_of(record)
        if reason:
            status, justification, needs_human = REASON_MAP[reason]
            findings.append(
                Finding(
                    rule="build-cve-status",
                    conclusion=f"{reason} -> {status.value}",
                    evidence=record.detail,
                    source=record.source,
                )
            )
            result.status = status
            result.justification = justification
            result.requires_human = needs_human
            result.confidence = Confidence.MEDIUM if needs_human else Confidence.HIGH
            if status is VexStatus.NOT_AFFECTED and justification is None:
                result.impact_statement = (
                    f"Marked {reason} in the build metadata: {record.detail or 'no justification recorded'}. "
                    "Confirm the justification still holds for this release."
                )
            if status is VexStatus.FIXED and record.fixed_version:
                findings.append(
                    Finding(
                        rule="build-fixed-version",
                        conclusion=f"fixed in {record.fixed_version}",
                        evidence=f"recipe reports the fix in {record.fixed_version}",
                        source=record.source,
                    )
                )
        else:
            # Fall back on the coarse group when no reason string was recorded.
            coarse = {
                BuildStatus.PATCHED: (VexStatus.FIXED, None, True),
                BuildStatus.IGNORED: (VexStatus.NOT_AFFECTED, None, True),
                BuildStatus.UNPATCHED: (VexStatus.AFFECTED, None, False),
                BuildStatus.UNKNOWN: (VexStatus.UNDER_INVESTIGATION, None, True),
            }[record.status]
            status, justification, needs_human = coarse
            findings.append(
                Finding(
                    rule="build-status-group",
                    conclusion=f"{record.status.value} -> {status.value}",
                    evidence="no CVE_STATUS reason string was recorded, only the group",
                    source=record.source,
                )
            )
            result.status = status
            result.requires_human = needs_human
            result.confidence = Confidence.LOW if needs_human else Confidence.MEDIUM
            if status is VexStatus.NOT_AFFECTED:
                result.impact_statement = (
                    "The build marked this ignored without recording a reason. "
                    "A published not_affected needs a justification a reader can check."
                )
            if status is VexStatus.FIXED:
                result.impact_statement = (
                    "The build reports a patch was applied. That is evidence, not proof: "
                    "confirm the patch addresses this CVE in this version."
                )
    else:
        findings.append(
            Finding(
                rule="not-in-build-metadata",
                conclusion="present in the image, no CVE record",
                evidence=f"{component.name} {component.version} ships, but no scanner "
                "record mentions this CVE",
                source="inventory",
            )
        )
        result.status = VexStatus.UNDER_INVESTIGATION
        result.requires_human = True
        result.confidence = Confidence.LOW

    # Rule 3 - kernel configuration gating. Can only downgrade, never upgrade.
    gate = _config_gate(product, component, gate_symbols)
    if gate is not None:
        gated_out, evidence = gate
        findings.append(
            Finding(
                rule="kernel-config-gate",
                conclusion="vulnerable code not built"
                if gated_out
                else "vulnerable code built in",
                evidence=evidence,
                source="kernel .config",
            )
        )
        if gated_out and result.status is VexStatus.AFFECTED:
            result.status = VexStatus.NOT_AFFECTED
            result.justification = Justification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH
            result.confidence = Confidence.HIGH
            result.requires_human = False

    if result.status is VexStatus.AFFECTED and not result.action_statement:
        fixed_hint = (
            record.fixed_version if record and record.fixed_version else advisory_fixed_version
        )
        result.action_statement = (
            f"Update {component.name} to {fixed_hint} or later and ship a security update."
            if fixed_hint
            else f"No fixed version is recorded for {component.name} {component.version}. "
            "Apply the upstream patch, or a mitigating measure, and record which."
        )

    result.findings = findings
    return result


def triage(
    product: Product,
    cve: str,
    *,
    actively_exploited: bool | None = None,
    advisory_fixed_version: str | None = None,
    advisory_introduced: str | None = None,
    advisory_last_affected: str | None = None,
    gate_symbols: list[str] | None = None,
    candidates: list[Component] | None = None,
    enrichment: Enrichment | None = None,
) -> Triage:
    """Decide a product's status for one CVE.

    ``candidates`` lets a feed client narrow the components to examine when it
    already knows which package the advisory names. Without it, the components
    carrying a record for this CVE are used, which is what a build-tree scan
    gives you.
    """
    cve = cve.strip().upper()

    # Feed data fills arguments the caller did not supply. It never overrides
    # one that was supplied: an explicit --actively-exploited no is a human
    # decision, and a feed does not get to overturn it.
    feed_notes: list[Finding] = []
    if enrichment is not None:
        if actively_exploited is None:
            actively_exploited = enrichment.actively_exploited
        advisory_fixed_version = advisory_fixed_version or enrichment.fixed_version or None
        advisory_introduced = advisory_introduced or enrichment.introduced or None
        advisory_last_affected = advisory_last_affected or enrichment.last_affected or None
        feed_notes = [
            Finding(
                rule=f"feed:{item.source}",
                conclusion=item.statement,
                evidence=item.detail,
                source=item.source,
            )
            for item in enrichment.evidence
        ]

    if candidates is None:
        candidates = [c for c, _ in product.bearing(cve)]

    triaged = [
        triage_component(
            product,
            c,
            cve,
            advisory_fixed_version=advisory_fixed_version,
            advisory_introduced=advisory_introduced,
            advisory_last_affected=advisory_last_affected,
            gate_symbols=gate_symbols,
        )
        for c in candidates
    ]

    if not triaged:
        result = Triage(
            cve=cve,
            product=product.name,
            status=VexStatus.NOT_AFFECTED,
            summary=(
                f"No component in {product.name} {product.version} carries {cve}. "
                "Record the negative finding in your evidence; do not report."
            ),
        )
        result.components = []
        result.reportable = False
        result.reportable_reason = "the product does not contain the vulnerable component"
        if enrichment is not None:
            result.enrichment = enrichment.to_dict()
        return result

    # Aggregate: the worst status wins, because a product is affected if any part is.
    precedence = [
        VexStatus.NOT_AFFECTED,
        VexStatus.FIXED,
        VexStatus.UNDER_INVESTIGATION,
        VexStatus.AFFECTED,
    ]
    overall = max((c.status for c in triaged), key=precedence.index)

    result = Triage(
        cve=cve,
        product=product.name,
        status=overall,
        components=triaged,
        requires_human=any(c.requires_human for c in triaged),
    )
    if enrichment is not None:
        result.enrichment = enrichment.to_dict()
        # Feed findings go on every component, because they are facts about the
        # vulnerability rather than about one package.
        for comp in triaged:
            comp.findings.extend(feed_notes)

    affected = [c for c in triaged if c.status is VexStatus.AFFECTED]
    if overall is VexStatus.AFFECTED:
        names = ", ".join(f"{c.component} {c.version}" for c in affected)
        result.summary = (
            f"{cve} is unpatched in {names}, shipped in {product.name} {product.version}."
        )
        if actively_exploited is True:
            result.reportable = True
            result.reportable_reason = (
                "Article 14(1): the vulnerability is contained in the product and is "
                "actively exploited. The 24-hour clock is running."
            )
        elif actively_exploited is False:
            result.reportable = False
            result.reportable_reason = (
                "Affected, but no evidence of active exploitation. Article 14(1) is not "
                "triggered. Fix it under Annex I Part II; do not file an early warning."
            )
        else:
            result.reportable = False
            result.reportable_reason = (
                "Affected, exploitation status unknown. Article 14(1) turns on active "
                "exploitation — establish that before filing, and record when you did."
            )
    elif overall is VexStatus.FIXED:
        result.summary = (
            f"{cve} is present in {product.name} {product.version} but "
            "already fixed in this build. Publish a VEX 'fixed' statement "
            "rather than an Article 14 report."
        )
        result.reportable_reason = "the shipped version is not vulnerable"
    elif overall is VexStatus.UNDER_INVESTIGATION:
        result.summary = (
            f"{cve} touches {product.name} {product.version} but the "
            "evidence is not conclusive. Publish under_investigation and "
            "resolve it before the 72-hour stage."
        )
        result.reportable_reason = "status unresolved; do not file on a guess"
        result.requires_human = True
    else:
        result.summary = (
            f"{cve} does not affect {product.name} {product.version}. "
            "Publish the not_affected statement so your customers' "
            "scanners stop asking."
        )
        result.reportable_reason = "the product is not affected"

    return result
