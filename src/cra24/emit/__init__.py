# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Emitters: render the canonical model into the formats other people consume."""

from . import csaf, srp, validate, vex
from .csaf import build as csaf_document
from .csaf import tracking_id
from .srp import Dossier, to_markdown
from .srp import build as srp_dossier
from .validate import validate_csaf, validate_openvex
from .vex import build as openvex_document
from .vex import document_id

__all__ = [
    "Dossier",
    "csaf",
    "csaf_document",
    "document_id",
    "openvex_document",
    "srp",
    "srp_dossier",
    "to_markdown",
    "tracking_id",
    "validate",
    "validate_csaf",
    "validate_openvex",
    "vex",
]
