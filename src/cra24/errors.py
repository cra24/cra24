# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Exception hierarchy.

Library code raises these. Only ``cli.py`` is allowed to turn them into exit
codes, because a library that calls ``SystemExit`` is a library nobody can embed.
"""

from __future__ import annotations


class Cra24Error(Exception):
    """Base for every error this package raises deliberately."""

    exit_code = 1

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message if not self.hint else f"{self.message}\n  hint: {self.hint}"


class IngestError(Cra24Error):
    """A build tree or SBOM could not be read into the model."""

    exit_code = 2


class ConfigError(Cra24Error):
    """The product configuration is missing or malformed."""

    exit_code = 3


class ValidationError(Cra24Error):
    """An emitted document failed schema validation."""

    exit_code = 4


class EvidenceError(Cra24Error):
    """The evidence ledger is missing, unreadable, or broken."""

    exit_code = 5


class DossierIncomplete(Cra24Error):
    """A required reporting field has no value.

    Carries the offending field keys so the CLI can print them as a checklist
    rather than a wall of prose.
    """

    exit_code = 6

    def __init__(self, message: str, gaps: list[str], *, hint: str | None = None) -> None:
        super().__init__(message, hint=hint)
        self.gaps = gaps
