# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Product configuration, and access to the bundled regulation data.

The configuration file carries the things a build tree cannot know: who you are,
which Member States you sell into, which Annex class you fall under, who your
coordinator CSIRT is. It is separate from the scanned inventory on purpose —
the inventory changes with every build, the identity almost never does.
"""

from __future__ import annotations

import json
import sys
from functools import cache
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .model import ANNEX_CLASSES, EU_MEMBER_STATES, Manufacturer, Product

DATA_DIR = Path(__file__).resolve().parent / "data"
SCHEMA_DIR = DATA_DIR / "schemas"

_PRODUCT_KEYS = (
    "name",
    "version",
    "member_states",
    "support_period_end",
    "annex_class",
    "machine",
    "image",
    "build_id",
)


@cache
def srp_spec() -> dict[str, Any]:
    """The versioned ENISA SRP field spec bundled with this release."""
    return json.loads((DATA_DIR / "srp-fields.json").read_text(encoding="utf-8"))


@cache
def annex_spec() -> dict[str, Any]:
    """Annex III and Annex IV classification data."""
    return json.loads((DATA_DIR / "annex.json").read_text(encoding="utf-8"))


def stage_spec(stage_id: str) -> dict[str, Any]:
    for stage in srp_spec()["stages"]:
        if stage["id"] == stage_id:
            return stage
    raise ConfigError(
        f"unknown SRP stage {stage_id!r}",
        hint="one of: " + ", ".join(s["id"] for s in srp_spec()["stages"]),
    )


def stage_fields(stage_id: str) -> list[dict[str, Any]]:
    """Fields for a stage, including everything inherited from earlier stages."""
    stage = stage_spec(stage_id)
    fields: list[dict[str, Any]] = []
    parent = stage.get("inherits")
    if parent:
        fields.extend(stage_fields(parent))
    seen = {f["key"] for f in fields}
    fields.extend(f for f in stage["fields"] if f["key"] not in seen)
    return fields


def load_raw(path: str | Path) -> dict[str, Any]:
    """Read a config file. JSON always; TOML where the interpreter has ``tomllib``."""
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"{p} does not exist", hint="write one with `cra24 init`")
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".toml":
        if sys.version_info < (3, 11):  # pragma: no cover - interpreter dependent
            raise ConfigError(
                "TOML config needs Python 3.11 or newer",
                hint="use JSON, or upgrade the interpreter",
            )
        import tomllib  # type: ignore[import-not-found]

        try:
            return tomllib.loads(text)
        except Exception as exc:
            raise ConfigError(f"{p} is not valid TOML: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"{p} is not valid JSON: {exc}", hint=f"line {exc.lineno}, column {exc.colno}"
        ) from exc


def validate_config(cfg: dict[str, Any]) -> list[str]:
    """Structural problems in a config file, before it touches a Product."""
    problems: list[str] = []
    unknown = sorted(set(cfg) - set(_PRODUCT_KEYS) - {"manufacturer", "notes", "$schema"})
    if unknown:
        problems.append(f"unrecognised top-level keys: {', '.join(unknown)}")
    ms = cfg.get("member_states")
    if ms is not None:
        if not isinstance(ms, list):
            problems.append("member_states must be a list of ISO 3166-1 alpha-2 codes")
        else:
            bad = [m for m in ms if not isinstance(m, str) or m.upper() not in EU_MEMBER_STATES]
            if bad:
                problems.append(f"member_states contains non-EU codes: {bad}")
    ac = cfg.get("annex_class")
    if ac is not None and ac not in ANNEX_CLASSES:
        problems.append(f"annex_class must be one of {', '.join(ANNEX_CLASSES)}, got {ac!r}")
    man = cfg.get("manufacturer")
    if man is not None:
        if not isinstance(man, dict):
            problems.append("manufacturer must be an object")
        else:
            known = set(Manufacturer.__dataclass_fields__)
            extra = sorted(set(man) - known)
            if extra:
                problems.append(f"unrecognised manufacturer keys: {', '.join(extra)}")
    return problems


def apply(product: Product, cfg: dict[str, Any]) -> Product:
    """Overlay a config onto a scanned product, in place."""
    problems = validate_config(cfg)
    if problems:
        raise ConfigError("the configuration has problems:\n  - " + "\n  - ".join(problems))
    man = cfg.get("manufacturer")
    if man:
        product.manufacturer = Manufacturer(**man)
    for key in _PRODUCT_KEYS:
        if key in cfg and cfg[key] not in (None, ""):
            value = cfg[key]
            if key == "member_states":
                value = [str(m).upper() for m in value]
            setattr(product, key, value)
    return product


def load(product: Product, path: str | Path) -> Product:
    return apply(product, load_raw(path))


def template(name: str = "MyProduct", version: str = "1.0.0") -> dict[str, Any]:
    """A starting config with every field present and commented by example."""
    return {
        "name": name,
        "version": version,
        "member_states": ["FR", "DE", "BE"],
        "annex_class": "important-i",
        "support_period_end": "2031-09-01",
        "manufacturer": {
            "name": "Example Embedded SAS",
            "country": "FR",
            "coordinator_csirt": "CERT-FR",
            "assigned_representative": "Name of the natural person registered with the SRP",
            "contact_email": "psirt@example.invalid",
            "security_contact_url": "https://example.invalid/security",
            "csaf_namespace": "https://example.invalid",
        },
        "notes": [
            "annex_class drives your conformity assessment route, not your Article 14 duty.",
            "coordinator_csirt is fixed by your Member State of main establishment and is "
            "chosen once, at SRP registration. Choosing the wrong one invalidates a "
            "notification and forces a resubmission.",
            "assigned_representative must hold a working EU Login account with MFA before "
            "an incident. Registration cannot be done retroactively.",
        ],
    }
