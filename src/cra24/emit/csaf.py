# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""CSAF 2.0 advisory in the VEX profile: what you hand your customers.

Article 14(8) requires informing impacted users about a vulnerability and about
the corrective measures they can take, in a machine-readable format where
possible. A CSAF advisory is that format. It is also what a downstream integrator
subjecting *you* to their own CRA duties will ask for, and the thing an embedded
supplier is least likely to have.

Three details separate an advisory that works from one that merely validates:

* **The product tree models the component inside the product.** A bare
  "product X is affected" tells an integrator nothing about which of their
  scanners' findings it answers. Components are emitted as their own products and
  joined to the firmware with a ``default_component_of`` relationship, so the
  statement is about *openssl 3.0.12 as shipped in Gateway 2.4.0*, which is what a
  scanner can actually match.
* **Every ``known_not_affected`` product carries a flag.** The VEX profile
  requires a machine-readable justification for a negative claim, and an advisory
  without one is an assertion a reader has no way to check.
* **Product identification helpers carry the purl.** Without one, matching falls
  back to string comparison of product names, which fails silently.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .. import __version__
from ..model import Product
from ..triage import CSAF_FLAG, CSAF_STATUS, ComponentTriage, Triage, VexStatus

PRODUCT_ID = "CSAFPID-0001"

_TLP_URL = "https://www.first.org/tlp/"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _component_pid(index: int) -> str:
    return f"CSAFPID-01{index:02d}"


def _relationship_pid(index: int) -> str:
    return f"CSAFPID-02{index:02d}"


def _helper(comp: ComponentTriage) -> dict[str, Any]:
    helper: dict[str, Any] = {}
    if comp.purl:
        helper["purl"] = comp.purl
    return {"product_identification_helper": helper} if helper else {}


def _product_tree(product: Product, triaged: list[ComponentTriage]) -> dict[str, Any]:
    vendor = product.manufacturer.name or "unknown vendor"
    full_name = f"{product.name} {product.version}".strip() or "product"

    branches: list[dict[str, Any]] = [
        {
            "category": "vendor",
            "name": vendor,
            "branches": [
                {
                    "category": "product_name",
                    "name": product.name or "product",
                    "branches": [
                        {
                            "category": "product_version",
                            "name": product.version or "unversioned",
                            "product": {"name": full_name, "product_id": PRODUCT_ID},
                        }
                    ],
                }
            ],
        }
    ]

    relationships: list[dict[str, Any]] = []
    for i, comp in enumerate(triaged, start=1):
        cpid = _component_pid(i)
        branches.append(
            {
                "category": "product_name",
                "name": comp.component,
                "branches": [
                    {
                        "category": "product_version",
                        "name": comp.version or "unversioned",
                        "product": {
                            "name": f"{comp.component} {comp.version}".strip(),
                            "product_id": cpid,
                            **_helper(comp),
                        },
                    }
                ],
            }
        )
        relationships.append(
            {
                "category": "default_component_of",
                "product_reference": cpid,
                "relates_to_product_reference": PRODUCT_ID,
                "full_product_name": {
                    "name": f"{comp.component} {comp.version} as a component of {full_name}".strip(),
                    "product_id": _relationship_pid(i),
                },
            }
        )

    tree: dict[str, Any] = {"branches": branches}
    if relationships:
        tree["relationships"] = relationships
    return tree


def build(
    product: Product,
    result: Triage,
    tracking_id: str,
    *,
    version: str = "1",
    tlp: str = "WHITE",
    advisory_notes: str = "",
) -> dict[str, Any]:
    """Assemble a CSAF 2.0 document in the ``csaf_vex`` profile."""
    now = _now()
    triaged = result.components
    full_name = f"{product.name} {product.version}".strip() or "product"

    status: dict[str, list[str]] = {}
    flags: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []
    threats: list[dict[str, Any]] = []
    notes: list[dict[str, Any]] = []

    if not triaged:
        # Nothing carries the identifier: the product itself is not affected.
        status["known_not_affected"] = [PRODUCT_ID]
        flags.append(
            {
                "label": "component_not_present",
                "product_ids": [PRODUCT_ID],
            }
        )
    for i, comp in enumerate(triaged, start=1):
        pid = _relationship_pid(i)
        status.setdefault(CSAF_STATUS[comp.status], []).append(pid)

        if comp.status is VexStatus.NOT_AFFECTED:
            if comp.justification is not None:
                flags.append({"label": CSAF_FLAG[comp.justification], "product_ids": [pid]})
            else:
                # The profile wants a machine-readable justification for every
                # negative claim. Without one, say so as a threat rather than
                # emitting a bare assertion.
                threats.append(
                    {
                        "category": "impact",
                        "details": comp.impact_statement
                        or "Assessed as not affected; justification pending review.",
                        "product_ids": [pid],
                    }
                )
        elif comp.status is VexStatus.AFFECTED:
            remediations.append(
                {
                    "category": "vendor_fix"
                    if "Update" in comp.action_statement
                    else "none_available",
                    "details": comp.action_statement
                    or "A corrective measure is being prepared.",
                    "product_ids": [pid],
                }
            )
        elif comp.status is VexStatus.FIXED and comp.impact_statement:
            notes.append(
                {
                    "category": "other",
                    "title": f"{comp.component} caveat",
                    "text": comp.impact_statement,
                }
            )

    status = {k: sorted(set(v)) for k, v in sorted(status.items())}

    notes.insert(
        0,
        {
            "category": "summary",
            "title": "Summary",
            "text": result.summary or f"Impact of {result.cve} on {full_name}.",
        },
    )
    if advisory_notes:
        notes.append({"category": "general", "title": "Notes", "text": advisory_notes})
    notes.append(
        {
            "category": "legal_disclaimer",
            "title": "Terms of use",
            "text": (
                "This advisory was drafted with cra24, an unofficial tool not "
                "affiliated with ENISA or the European Commission. It reflects the "
                "issuing manufacturer's assessment and nothing else."
            ),
        }
    )

    vulnerability: dict[str, Any] = {
        "cve": result.cve if result.cve.upper().startswith("CVE-") else None,
        "product_status": status,
        "notes": [
            {
                "category": "description",
                "title": "Assessment",
                "text": result.summary or f"Assessment of {result.cve}.",
            }
        ],
    }
    if vulnerability["cve"] is None:
        del vulnerability["cve"]
        vulnerability["ids"] = [{"system_name": "cra24", "text": result.cve}]
    if flags:
        vulnerability["flags"] = flags
    if remediations:
        vulnerability["remediations"] = remediations
    if threats:
        vulnerability["threats"] = threats

    document: dict[str, Any] = {
        "category": "csaf_vex",
        "csaf_version": "2.0",
        "title": f"{full_name}: {result.cve}",
        "lang": "en",
        "publisher": {
            "category": "vendor",
            "name": product.manufacturer.name or "unknown vendor",
            "namespace": (
                product.manufacturer.csaf_namespace
                or product.manufacturer.security_contact_url
                or "https://example.invalid"
            ),
        },
        "notes": notes,
        "distribution": {
            "text": f"TLP:{tlp}",
            "tlp": {"label": tlp, "url": _TLP_URL},
        },
        "tracking": {
            "id": tracking_id,
            "status": "final",
            "version": version,
            "initial_release_date": now,
            "current_release_date": now,
            "generator": {
                "date": now,
                "engine": {"name": "cra24", "version": __version__},
            },
            "revision_history": [
                {
                    "number": version,
                    "date": now,
                    "summary": "Initial release" if version == "1" else "Update",
                },
            ],
        },
    }
    if product.manufacturer.contact_email:
        document["publisher"]["contact_details"] = product.manufacturer.contact_email

    return {
        "document": document,
        "product_tree": _product_tree(product, triaged),
        "vulnerabilities": [vulnerability],
    }


def tracking_id(product: Product, cve: str) -> str:
    """A stable, readable advisory id: ``VENDOR-PRODUCT-CVE``."""

    def slug(value: str) -> str:
        return "".join(ch if ch.isalnum() else "-" for ch in value.upper()).strip("-")

    vendor = slug(product.manufacturer.name or "VENDOR")[:24]
    name = slug(product.name or "PRODUCT")[:24]
    return "-".join(p for p in (vendor, name, slug(cve)) if p)


# Backwards-compatible name from 0.1.
def csaf_vex(
    product: Product, cve: str, tid: str, summary: str = "", notes: str = ""
) -> dict[str, Any]:
    from ..triage import triage as run_triage

    result = run_triage(product, cve)
    if summary:
        result.summary = summary
    return build(product, result, tid, advisory_notes=notes)
