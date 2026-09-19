# Contributing to cra24

Thank you for considering it. This document covers the practical parts; the
licensing part is in [CLA.md](CLA.md) and is worth reading before you write code,
because it is the one thing that cannot be sorted out afterwards.

---

## The most valuable contribution

**Field spec drift.** If you have used the ENISA Single Reporting Platform and
the form does not match what `cra24 spec` prints, open a *field spec drift*
issue. Say what you saw, at which stage, and whether the field was mandatory.

`src/cra24/data/srp-fields.json` should be the most accurate public description
of that form that exists. It only gets there if people who have seen it say so.
ENISA publishes no machine-readable spec and no API, so this file is
reconstructed from documentation and reports — it is exactly as good as the
reports it receives.

You do not need to write any code for this, and it is worth more than most
patches.

---

## Before you write code

### Sign the CLA

Add a `Signed-off-by` trailer to every commit:

```bash
git commit -s -m "your message"
```

That trailer certifies you have read the [CLA](CLA.md) and can grant the licences
it describes. CI checks for it. A first-time contributor is also asked, once, to
confirm in the pull request thread.

**Why:** cra24 is dual-licensed. Only the copyright holder can offer a work under
a second licence, so a contribution that arrived under the AGPL alone would make
the commercial licence unofferable over any code containing it. The CLA grants a
parallel licence; you keep your copyright, and the project undertakes in writing
(CLA section 7) that your contribution stays available under the AGPL for as long
as the project distributes it at all.

If that trade is not one you want to make, open an issue describing the change
instead. A maintainer can implement it independently.

### Open an issue first for anything large

A new ingester, a new emitter, or a change to the triage rules is worth agreeing
on before it is written. Small fixes can go straight to a pull request.

---

## Setting up

```bash
git clone https://github.com/cra24/cra24
cd cra24
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest
```

The fixtures under `tests/fixtures/` are hand-written miniatures of real build
trees. You do not need Yocto or Buildroot installed to work on cra24.

---

## The standards this codebase holds itself to

These are not style preferences. They are the reasons the tool can be trusted
with a legal deadline.

### 1. Every conclusion carries its evidence

A verdict is never a bare status. It is a status, a confidence level, and the
ordered list of rules that fired, each with the file it read. If you add a rule,
it appends a `Finding`. No exceptions.

```python
findings.append(Finding(
    rule="kernel-config-gate",
    conclusion="vulnerable code not built",
    evidence="not set in the shipped kernel config: CONFIG_KSMBD",
    source="kernel .config"))
```

### 2. Absent evidence never becomes a favourable conclusion

The asymmetry is deliberate and it runs one way only:

- A rule may **downgrade** `affected` to `not_affected` when it has positive
  evidence that the code is not reachable.
- A rule may **never upgrade** a negative verdict on the strength of missing data.
- "We looked and it is off" and "we never looked" must stay distinguishable all
  the way through. This is why `read_kernel_config` records unset symbols as
  `"n"` rather than omitting them.

A tool that guesses in the favourable direction is worse than no tool, because it
launders a guess into a published VEX statement.

### 3. Justifications come from the closed vocabulary

OpenVEX defines five justification labels. Free text is not one of them. If a
build system's reason string does not map onto the five, emit an
`impact_statement` instead and flag `requires_human` — do not invent a sixth
label, and do not pick the nearest one silently.

New reason strings go in `REASON_MAP` in `triage.py` with a comment explaining
the mapping. `test_triage.py` asserts that every justification in that table is a
real `Justification` and only ever appears alongside `not_affected`.

### 4. Library code does not exit

Everything raises from the `Cra24Error` hierarchy in `errors.py`. Only `cli.py`
turns an exception into an exit code. The same code path has to serve the CLI,
the coming watch daemon and the service; a library that calls `SystemExit` serves
none of them.

Errors carry a `hint` wherever there is a useful next action:

```python
raise IngestError(
    f"{build} does not look like a Yocto build directory (no tmp/)",
    hint="point --build-dir at the directory bitbake writes into")
```

### 5. Output is deterministic

Serialising the same inventory twice must produce identical bytes. Timestamps are
stamped once, at ingest, not at save time. The evidence ledger depends on this:
a spurious hash change is indistinguishable from a real one.

### 6. Regulation data is data

Field sets, deadlines and Annex categories live in `src/cra24/data/*.json`, with
`spec_version`, `sources` and — where public guidance disagrees with itself —
`known_disagreements`. They are not hardcoded, and a user must be able to patch
them without waiting for a release.

That directory is additionally offered under CC-BY-4.0. A mapping of a public
regulation should not be enclosed by anyone, including this project.

### 7. cra24 never claims to make anyone compliant

Not in the README, not in a docstring, not in emitted output, not in a commit
message. It organises evidence and drafts documents for a human to review. The
`NOTICE` disclaimer and the runtime `DISCLAIMER` string are load-bearing and are
asserted by tests.

---

## Tests

```bash
pytest                          # everything
pytest tests/test_triage.py -v  # one file
pytest --cov=cra24              # with coverage
```

What a pull request is expected to carry:

- **A new rule** needs a test for what it concludes *and* a test for what it
  refuses to conclude from absent data.
- **A new emitter field** needs a schema-validation test. `test_emit.py` asserts
  every generated document validates against the vendored official schema.
- **A bug fix** needs a test that fails before it and passes after. The
  recipe-to-package fix in 0.2.0 is the model here: the test says what silently
  went wrong and why it mattered.
- **A new source file** needs the SPDX header. `test_repo_hygiene.py` enforces it.

Tests are named as sentences. `test_a_recipe_built_but_not_installed_is_dropped`
tells a reader what the system promises; `test_yocto_3` does not.

---

## Style

```bash
ruff check . && ruff format --check .
mypy
```

Beyond the linter:

- Docstrings explain **why**, not what. The signature already says what.
- Comments belong where a reader would otherwise ask "is this a mistake?" — an
  ordering that matters, an asymmetry that looks like a bug, a workaround for a
  platform defect.
- No emoji, no exclamation marks, no marketing language in the codebase.

---

## Commits and pull requests

Commit subjects are imperative and specific:

```
ingest: map recipe names to installed packages

cve-check reports at recipe granularity while image manifests list
packages, so linux-raspberrypi was dropped for not appearing under its
own name — silently removing every kernel CVE from the dossier.

Signed-off-by: Your Name <you@example.com>
```

Pull requests should say what changed, why, and how you know it works. Link the
issue if there is one. If the change can alter a verdict for a CVE someone has
already published a VEX statement about, say so — it belongs in the changelog
under **Triage**.

---

## Security

Do not open a public issue for a vulnerability in cra24 itself. See
[SECURITY.md](SECURITY.md).

---

## Releasing

Maintainers only:

1. Update `CHANGELOG.md`, moving Unreleased into a dated section.
2. Bump `version` in `pyproject.toml` and `__version__` in `src/cra24/__init__.py`
   — a test asserts they match.
3. If the field spec changed, bump `spec_version` in `srp-fields.json` and add a
   **Field spec** entry to the changelog.
4. Tag `vX.Y.Z`. The release workflow builds and publishes.
