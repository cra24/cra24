# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Repository hygiene: provenance you can point an auditor at.

A dual-licensed project lives on provenance. A source file without an SPDX
header is one whose licence a court would have to infer, and an inferred licence
is what the commercial offer cannot rest on. So the header is not decoration
here, and it is cheaper to enforce it on every commit than to reconstruct the
intent of a file three years after the contributor has moved on.

The last test in this module guards the CI workflow itself: a job that runs a
test file which does not exist fails on the runner and tells you nothing useful
about the code. That is not hypothetical — this module was added precisely
because ``ci.yml`` referenced it before it existed.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

#: The header every source file carries, e.g. ``# SPDX-License-Identifier: AGPL-3.0-only``.
SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*(?P<licence>\S+)")
COPYRIGHT_RE = re.compile(r"Copyright \(C\) \d{4}")

#: Source files whose licence must be unambiguous. Data fixtures, generated
#: output and GitHub's own YAML are deliberately not in scope: nobody compiles
#: them into a product, so nothing turns on their provenance.
SOURCE_SUFFIXES = {".py", ".service", ".timer"}

#: How far into a file the header may appear. Far enough for a shebang and an
#: encoding line, close enough that it is still the first thing a reader sees.
HEADER_LINES = 5


def _tracked_files() -> list[Path]:
    """Every file git knows about, or the working tree if git is unavailable.

    The fallback matters: an sdist unpacked on a build machine has no ``.git``,
    and this suite should still be runnable there.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "-z"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout
        paths = [REPO / p for p in out.split("\0") if p]
        if paths:
            return paths
    except (OSError, subprocess.SubprocessError):
        pass

    skip = {".git", ".venv", "venv", "__pycache__", "dist", "build", ".mypy_cache"}
    return [
        p for p in REPO.rglob("*") if p.is_file() and not any(part in skip for part in p.parts)
    ]


def _source_files() -> list[Path]:
    return sorted(p for p in _tracked_files() if p.suffix in SOURCE_SUFFIXES and p.is_file())


def _declared_licence() -> str:
    """The licence ``pyproject.toml`` declares, read without a TOML parser.

    ``tomllib`` is 3.11+, and this project still supports 3.10.
    """
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^license\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "pyproject.toml declares no licence"
    return match.group(1)


def _header(path: Path) -> str:
    with path.open(encoding="utf-8", errors="replace") as fh:
        return "".join(next(fh, "") for _ in range(HEADER_LINES))


def test_there_are_source_files_to_check() -> None:
    """Guard against the enumeration silently returning nothing.

    Every assertion below is a loop over this list. If it were ever empty the
    whole module would pass while checking nothing at all, which is the one
    outcome worse than failing.
    """
    files = _source_files()
    assert len(files) >= 30, f"only found {len(files)} source files; enumeration is broken"


@pytest.mark.parametrize("path", _source_files(), ids=lambda p: str(p.relative_to(REPO)))
def test_every_source_file_carries_an_spdx_header(path: Path) -> None:
    match = SPDX_RE.search(_header(path))
    assert match, (
        f"{path.relative_to(REPO)} has no SPDX-License-Identifier in its first "
        f"{HEADER_LINES} lines"
    )


@pytest.mark.parametrize("path", _source_files(), ids=lambda p: str(p.relative_to(REPO)))
def test_every_source_file_carries_a_copyright_line(path: Path) -> None:
    assert COPYRIGHT_RE.search(_header(path)), (
        f"{path.relative_to(REPO)} has no copyright line in its first {HEADER_LINES} lines"
    )


def test_every_header_agrees_with_the_declared_licence() -> None:
    """One file under a different licence would make the whole tree ambiguous."""
    declared = _declared_licence()
    wrong = {}
    for path in _source_files():
        match = SPDX_RE.search(_header(path))
        if match and match.group("licence") != declared:
            wrong[str(path.relative_to(REPO))] = match.group("licence")
    assert not wrong, f"pyproject.toml declares {declared}, but these disagree: {wrong}"


def test_ci_only_runs_test_files_that_exist() -> None:
    """A CI job pointing at a missing test file fails for the wrong reason.

    pytest exits 4 (usage error) when handed a path that is not there, so the
    job goes red while the code under it is fine — and a red build that means
    nothing is a build people learn to ignore.
    """
    workflows = sorted((REPO / ".github" / "workflows").glob("*.yml"))
    if not workflows:
        pytest.skip("no workflows in this checkout")

    missing: list[str] = []
    for workflow in workflows:
        for line in workflow.read_text(encoding="utf-8").splitlines():
            if "pytest" not in line:
                continue
            for token in re.findall(r"[\w./-]+\.py", line):
                if not (REPO / token).exists():
                    missing.append(f"{workflow.name}: {token}")

    assert not missing, "CI runs test paths that do not exist: " + ", ".join(missing)
