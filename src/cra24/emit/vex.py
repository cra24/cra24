# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""OpenVEX statements: the short form, for pipelines and scanners.

CSAF is what a human integrator reads. OpenVEX is what ``trivy``, ``grype`` and
the rest consume to stop reporting a finding you have already answered. Publishing
both is not redundancy; they are read by different things.

Conformance notes, because the spec has teeth in places tools commonly miss:

* ``@context`` must be the exact version IRI. Anything else and a strict parser
  rejects the document.
* ``version`` is an integer that **must increment** whenever content changes. A
  document that keeps re-publishing version 1 is one consumers cache and ignore.
* ``not_affected`` requires either a ``justification`` from the closed vocabulary
  or an ``impact_statement``. Emitting neither is the single most common way an
  OpenVEX document turns out to be invalid.
* ``affected`` should carry an ``action_statement``, and if it does, the spec
  expects an ``action_statement_timestamp`` alongside it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..model import Product
from ..triage import Triage, VexStatus

CONTEXT = "https://openvex.dev/ns/v0.2.0"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build(
    product: Product,
    result: Triage,
    doc_id: str,
    *,
    version: int = 1,
    author: str = "",
    role: str = "",
) -> dict[str, Any]:
    """Assemble an OpenVEX document for one CVE across a product's components."""
    now = _now()
    statements: list[dict[str, Any]] = []

    product_id = (
        f"pkg:generic/{product.name}@{product.version}"
        if product.name
        else "pkg:generic/product"
    )

    if not result.components:
        statements.append(
            {
                "vulnerability": {"name": result.cve},
                "products": [{"@id": product_id}],
                "status": VexStatus.NOT_AFFECTED.value,
                "justification": "component_not_present",
                "status_notes": result.summary,
                "timestamp": now,
            }
        )

    for comp in result.components:
        statement: dict[str, Any] = {
            "vulnerability": {"name": result.cve},
            "products": [
                {
                    "@id": comp.purl,
                    "subcomponents": [],
                }
            ],
            "status": comp.status.value,
            "timestamp": now,
        }
        # A component inside a product is expressed as the product carrying the
        # component as a subcomponent. That is what lets a scanner match a finding
        # on the component to a statement about the firmware.
        statement["products"] = [
            {
                "@id": product_id,
                "subcomponents": [{"@id": comp.purl}],
            }
        ]

        if comp.status is VexStatus.NOT_AFFECTED:
            if comp.justification is not None:
                statement["justification"] = comp.justification.value
            else:
                statement["impact_statement"] = (
                    comp.impact_statement
                    or "Assessed as not affected; justification pending review."
                )
        elif comp.status is VexStatus.AFFECTED and comp.action_statement:
            statement["action_statement"] = comp.action_statement
            statement["action_statement_timestamp"] = now

        if comp.impact_statement and "impact_statement" not in statement:
            statement["status_notes"] = comp.impact_statement

        statements.append(statement)

    doc: dict[str, Any] = {
        "@context": CONTEXT,
        "@id": doc_id,
        "author": author or product.manufacturer.name or "unknown",
        "timestamp": now,
        "version": int(version),
        "tooling": "cra24",
        "statements": statements,
    }
    if role:
        doc["role"] = role
    return doc


def document_id(product: Product, cve: str, *, version: int = 1) -> str:
    """A resolvable-looking ``@id`` under the manufacturer's own namespace."""
    base = (
        product.manufacturer.csaf_namespace
        or product.manufacturer.security_contact_url
        or "https://example.invalid"
    ).rstrip("/")
    slug = cve.lower().replace("/", "-")
    name = (product.name or "product").lower().replace(" ", "-")
    return f"{base}/vex/{name}/{slug}-{version}"


# Backwards-compatible name from 0.1.
def openvex(product: Product, cve: str, doc_id: str, justification: str = "") -> dict[str, Any]:  # noqa: ARG001
    from ..triage import triage as run_triage

    return build(product, run_triage(product, cve), doc_id)
