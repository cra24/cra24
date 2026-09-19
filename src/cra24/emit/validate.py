# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Schema validation for emitted documents.

A CSAF advisory that does not validate is one a customer's tooling silently
drops, which is worse than not publishing one: you believe you informed them and
you did not. So validation is not optional here — the CLI validates on every
emit and refuses to record an invalid artefact in the evidence ledger.

Schemas are vendored under ``data/schemas`` and resolved locally, because a build
machine on a factory network usually cannot reach ``docs.oasis-open.org`` and a
compliance tool that needs the internet to check its own output is not one you
can run during an incident.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

from ..config import SCHEMA_DIR
from ..errors import ValidationError
from ..versions import compare

#: External ``$ref`` targets in the CSAF schema mapped to vendored files.
LOCAL_REFS = {
    "https://www.first.org/cvss/cvss-v2.0.json": "cvss-v2.0.json",
    "https://www.first.org/cvss/cvss-v3.0.json": "cvss-v3.0.json",
    "https://www.first.org/cvss/cvss-v3.1.json": "cvss-v3.1.json",
}


@cache
def load_schema(filename: str) -> dict[str, Any]:
    path = SCHEMA_DIR / filename
    if not path.is_file():
        raise ValidationError(f"bundled schema {filename} is missing from the installation")
    return json.loads(path.read_text(encoding="utf-8"))


#: The jsonschema release that introduced the ``referencing`` registry that
#: :func:`_validator` passes. Older copies raise ``TypeError`` on ``registry=``.
MIN_JSONSCHEMA = "4.18"


def unavailable_reason() -> str:
    """Why validation cannot run, or ``""`` when it can.

    Checking ``jsonschema`` alone is not enough, and getting that wrong is how
    this went unnoticed: Ubuntu ships jsonschema 4.10 in ``dist-packages``
    without ``referencing``, so ``cra24 doctor`` reported the validator as
    present and the first ``cra24 report`` then died with a bare
    ``ModuleNotFoundError``. A green preflight followed by a crash during an
    incident is the worst way to learn that a dependency is missing, so the
    check covers everything :func:`_validator` actually imports.
    """
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        return "jsonschema is not installed"
    try:
        import referencing  # noqa: F401
    except ImportError:
        return "referencing is not installed"

    try:
        from importlib.metadata import version

        found = version("jsonschema")
    except Exception:  # pragma: no cover - metadata missing is not worth failing on
        return ""
    if compare(found, MIN_JSONSCHEMA) < 0:
        return f"jsonschema {found} is too old (need >= {MIN_JSONSCHEMA})"
    return ""


def available() -> bool:
    """Can a document actually be validated here?"""
    return not unavailable_reason()


def _validator(schema: dict[str, Any]):
    import jsonschema
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    resources = []
    for uri, filename in LOCAL_REFS.items():
        path = SCHEMA_DIR / filename
        if path.is_file():
            resources.append(
                (
                    uri,
                    Resource.from_contents(
                        json.loads(path.read_text(encoding="utf-8")),
                        default_specification=DRAFT202012,
                    ),
                )
            )
    registry = Registry().with_resources(resources)  # type: ignore[arg-type]
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema, registry=registry)


def validate(
    document: dict[str, Any], schema_file: str, *, label: str = "document", strict: bool = True
) -> list[str]:
    """Validate ``document``. Returns the list of problems.

    With ``strict``, a non-empty list is raised as a :class:`ValidationError`.
    Without ``jsonschema`` installed the function returns a single explanatory
    message rather than pretending the document passed.
    """
    reason = unavailable_reason()
    if reason:
        message = f"cannot validate the {label}: {reason} (pip install 'cra24[validate]')"
        if strict:
            raise ValidationError(
                message, hint="or pass --no-validate to emit without checking"
            )
        return [message]

    validator = _validator(load_schema(schema_file))
    problems = []
    for error in sorted(validator.iter_errors(document), key=lambda e: list(e.path)):
        where = "/".join(str(p) for p in error.path) or "(root)"
        problems.append(f"{where}: {error.message}")

    if problems and strict:
        raise ValidationError(
            f"the generated {label} does not validate against {schema_file}:\n  - "
            + "\n  - ".join(problems[:20]),
            hint="this is a bug in cra24 unless you edited the document by hand; "
            "please report it with the offending file",
        )
    return problems


def validate_csaf(document: dict[str, Any], strict: bool = True) -> list[str]:
    return validate(document, "csaf_json_schema.json", label="CSAF advisory", strict=strict)


def validate_openvex(document: dict[str, Any], strict: bool = True) -> list[str]:
    return validate(
        document, "openvex_json_schema.json", label="OpenVEX document", strict=strict
    )


def schema_inventory() -> list[dict[str, str]]:
    """What is bundled, for `cra24 doctor`."""
    out = []
    for path in sorted(Path(SCHEMA_DIR).glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        out.append(
            {
                "file": path.name,
                "id": doc.get("$id", ""),
                "title": doc.get("title", ""),
                "note": doc.get("x-cra24-note", ""),
            }
        )
    return out
