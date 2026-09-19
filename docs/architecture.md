# Architecture

## The shape

One canonical model in the middle, swappable readers on one side, swappable
renderers on the other.

```
  Yocto build tree ─┐                              ┌─ SRP dossier (JSON + Markdown)
  Buildroot output ─┤                              ├─ CSAF 2.0 advisory (VEX profile)
  CycloneDX SBOM   ─┼──► Product ──► triage ──────►┼─ OpenVEX 0.2.0
  SPDX SBOM        ─┤    (model)    (verdict +     ├─ evidence ledger record
  kernel .config   ─┘                evidence)     └─ (future: dashboards, feeds)
     ingest/                                           emit/
```

Adding a build system never touches an emitter. Adding an output format never
touches an ingester. That is the whole point of the middle layer, and it is the
property to preserve when extending this.

## The modules

| Module | Responsibility | Depends on |
| --- | --- | --- |
| `model.py` | The canonical shapes: `Product`, `Component`, `CveRecord`, `Manufacturer` | `errors`, `versions` |
| `versions.py` | Debian-rules version comparison and advisory range matching | nothing |
| `purl.py` | Package URL construction and parsing | nothing |
| `clock.py` | The Article 14 deadlines as `Obligation` objects | `errors` |
| `triage.py` | Affectedness rules → VEX status + evidence | `model`, `versions` |
| `evidence.py` | Hash-chained, optionally HMAC'd ledger | `errors` |
| `config.py` | Product configuration, and access to bundled regulation data | `model`, `errors` |
| `ingest/` | Build trees and SBOMs → `Product` | `model`, `purl` |
| `emit/` | `Product` + `Triage` → documents | `model`, `triage`, `clock`, `config` |
| `cli.py` | Argument parsing, presentation, exit codes | everything |

Dependencies point one way: `cli` → `emit` → `triage` → `model` → `versions`.
Nothing in `model` or below imports from `emit`, `ingest` or `cli`.

## Design decisions worth knowing

### The model keeps *why*, not just *what*

A component does not carry `{"CVE-2024-1086": "patched"}`. It carries a
`CveRecord` with the status, the reason string the build system recorded, the
human justification the recipe author wrote, and the file it all came from.

```python
CveRecord(
    id="CVE-2023-42364",
    status=BuildStatus.IGNORED,
    detail="not-applicable-config: CONFIG_AWK is not enabled in this defconfig",
    source="yocto:cve-summary.json",
)
```

In ten years, when someone asks why a product shipped with a known CVE marked
not-applicable, the `detail` field is the entire answer. Every other tool in this
space throws it away at ingest and cannot get it back.

### `BuildStatus` is not `VexStatus`

Two separate enums, deliberately:

- **`BuildStatus`** — what the build system said: `patched`, `ignored`,
  `unpatched`, `unknown`. A fact about a file on disk.
- **`VexStatus`** — what you publish: `not_affected`, `affected`, `fixed`,
  `under_investigation`. A claim you are making to your customers.

`triage.py` is the only thing that converts one into the other, and it records
how. Collapsing the two would make the tool's central judgement invisible.

### Triage rules are ordered and can only downgrade

The rules run in order, each appending a `Finding`:

1. **Advisory version range** — the most authoritative signal, because it comes
   from the people who fixed the bug. Returns early when it is conclusive.
2. **Build `CVE_STATUS` reason** — mapped through `REASON_MAP` to a VEX status
   and, where one exists, a justification from the closed vocabulary.
3. **Build status group** — the fallback when no reason string was recorded.
   Yields lower confidence and `requires_human`.
4. **Kernel config gate** — may turn `affected` into `not_affected`. It may
   **never** turn a negative verdict positive, and it does nothing at all when
   there is no config data.

The asymmetry in rule 4 is the safety property. See
[triage-rules.md](triage-rules.md).

### Regulation data is data

`src/cra24/data/srp-fields.json` and `annex.json` carry `spec_version`,
`sources`, and `known_disagreements`. The field spec is read at runtime; no field
name appears in the emitter code.

Two consequences, both intended:

- When ENISA moves the form, a user patches a JSON file. They do not wait for a
  release, and they do not fork.
- The condition grammar in the spec (`notification_type == 'Severe incident'`) is
  evaluated by a five-line parser, **never** by `eval`. That file is data a user
  can edit, and data never gets executed.

### Errors carry hints, and library code never exits

```python
raise IngestError(
    f"{build} does not look like a Yocto build directory (no tmp/)",
    hint="point --build-dir at the directory bitbake writes into")
```

Every exception derives from `Cra24Error` and carries an `exit_code`. Only
`cli.py` reads it. The same functions have to serve the CLI, the coming watch
daemon and the service.

### Output is byte-for-byte reproducible

`Product.to_dict()` does not invent a timestamp; `ingest/base.finish()` stamps
`scanned_at` once. Saving the same inventory twice produces identical bytes,
which the evidence ledger depends on — a spurious hash change is
indistinguishable from a real one.

---

## Adding an ingester

Three steps.

**1. Write the reader.** It returns a `Product` and raises `IngestError` with a
hint on anything it cannot read.

```python
# src/cra24/ingest/mybuild.py
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
from ..model import BuildStatus, Component, Product
from .base import finish, read_kernel_config

def load_mybuild(root, product_name="", product_version="", kernel_config=None):
    comps = {}
    # ... read the inventory the build already wrote ...
    comp = Component(name=name, version=version, origin="mybuild:manifest",
                     purl=purl_mod.for_component(name, version, "mybuild"))
    comp.add_cve(cve_id, BuildStatus.UNPATCHED, detail=reason, source="mybuild:scan")
    comps[name] = comp
    return finish(Product(name=..., components=list(comps.values())))
```

**2. Answer the question every ingester has to answer.** Which of these
components actually *ship*? A build system knows about far more than it installs.
Yocto's `cve-check` covers every recipe built; Buildroot's `pkg-stats` covers
every package enabled, host tools included. Claiming those ship overstates your
attack surface and wastes your own triage time.

Where the inventory and the CVE source use different names — Yocto's recipes
versus packages — build the map rather than dropping the mismatch. The
`linux-raspberrypi` / `kernel-image-image` case in `yocto.py` is the worked
example, and getting it wrong silently removed every kernel CVE from a dossier in
0.1.

**3. Wire it up.** Export it from `ingest/__init__.py`, add a `--mybuild-dir`
flag in `cli._source_args`, add a branch in `cli._load_product`, and add a
fixture under `tests/fixtures/`.

Fixtures are hand-written miniatures. Nobody should need Yocto installed to work
on cra24.

---

## Adding an emitter

An emitter is a pure function from `(Product, Triage)` to a dict.

```python
# src/cra24/emit/myformat.py
def build(product: Product, result: Triage, doc_id: str) -> dict:
    return {...}
```

Rules it must follow:

- **It does not decide anything.** All judgement happened in `triage.py`. An
  emitter that re-derives a status has put a second, divergent opinion into the
  system.
- **It validates.** If the format has a schema, vendor it under
  `data/schemas/`, add it to `NOTICE`, and add a test asserting that every
  generated document validates. `test_emit.py` does this for all three current
  emitters, including the empty and not-affected cases.
- **It carries the disclaimer.** Every emitted document says what produced it and
  that the tool is unofficial.

---

## Adding a triage rule

Read [CONTRIBUTING.md](../CONTRIBUTING.md) first — rules are the part of this
codebase with real consequences.

A rule appends a `Finding`, may downgrade a status, and must be tested twice:
once for what it concludes, and once for what it *refuses* to conclude when its
evidence is absent.

```python
gate = _config_gate(product, component, gate_symbols)
if gate is not None:                      # None means "no information"
    gated_out, evidence = gate
    findings.append(Finding(rule="kernel-config-gate", ...))
    if gated_out and result.status is VexStatus.AFFECTED:
        result.status = VexStatus.NOT_AFFECTED   # downgrade only
```

Note the shape: `None` for no information, a tuple for a conclusion. A boolean
would collapse "we looked and it is off" into "we never looked", which is the one
mistake this codebase is built to avoid.

---

## Where this is going

The layering is what makes the roadmap cheap:

- **Feed clients** (KEV, EPSS, OSV, NVD) become `feeds/`, filling the
  `advisory_fixed_version` and `actively_exploited` arguments `triage()` already
  takes.
- **Watch mode** is a loop over registered `product.json` files calling the same
  `triage()`.
- **The service** is a thin layer over the same functions — which is why library
  code raises instead of exiting.
- **The curated VEX feed** is a set of `ComponentTriage` results published as
  OpenVEX, produced by the emitter that already exists.

None of those need a new middle layer. See [roadmap.md](roadmap.md).
