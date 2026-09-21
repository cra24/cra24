# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Two kinds of change get called out specially, because they affect what you can
rely on:

- **Field spec** changes track the ENISA SRP form. They can alter which fields
  block a submission, so they are listed even when no code changed.
- **Triage** changes can alter the verdict for a CVE you already published a VEX
  statement about. Re-run and re-publish when you see one.

---

## [1.0.1] — 2026-09-21

Found by running `cra24 scan` against a real kernel and a real package list
rather than the fixtures. Both fixes affect verdicts.

### Triage

- **A kernel symbol whose name contains lower case was dropped entirely.**
  Kconfig symbols are conventionally upper case but not exclusively, and the
  pattern only allowed `[A-Z0-9_]`. A stock Ubuntu 6.8 config carries 36 enabled
  symbols it could not see — `CONFIG_SCSI_DC395x`, `CONFIG_MT76x02_LIB`,
  `CONFIG_ARCNET_COM90xx`, `CONFIG_MTD_NETtel` and others.

  A dropped `=y` or `=m` is worse than a parse error. The symbol becomes
  *absent*; absence in a complete config reads as "not enabled"; and the gate
  then reports a driver that is compiled in and shipping as `not_affected`,
  with an evidence line reading "not set in the shipped kernel config" about a
  symbol that is set. The one direction the engine must never fail in.

  **Re-run any dossier gated on a symbol containing a lower-case letter.**

### Fixed

- **`--kernel-config` now works with `--sbom`.** The flag sits in the shared
  inventory group, so it was offered alongside `--sbom`, accepted, and silently
  ignored: `load_sbom` never read it. Anyone gating an SBOM-described product
  got no gating at all and no warning. An SBOM lists packages, and a kernel CVE
  is answered by the configuration, so the flag belongs on that path too.

---

## [1.0.0] — 2026-09-19

First public release.

No functional change from 0.4.0. The version says 1.0 because the surface is
now one I am willing to keep stable: the CLI verbs and their exit codes, the
shape of `product.json`, and the emitted CSAF, OpenVEX and SRP documents. Those
are what a build pipeline and an auditor come to depend on, and breaking them
quietly is worse than a major version number.

Versions 0.1.0 through 0.4.0 were developed before publication and are not
tagged in this repository. The entries below are kept because they explain why
the engine behaves as it does — particularly which conclusions it refuses to
draw, and why.

---

## [0.4.0] — 2026-09-19

A correctness release. Nothing here is a new capability you asked for; it is
the set of things the engine was getting quietly wrong, found by reviewing it
against its own stated contracts.

### Triage

- **A kernel symbol that is merely *absent* no longer counts as "switched
  off".** `read_kernel_config` has always recorded an explicitly unset symbol as
  `n` so that "we looked and it is off" stays distinguishable from "we never
  looked"; the config gate then collapsed the two. In a kconfig-generated
  `.config` that was still right — every reachable symbol was considered when
  the file was written — but `--kernel-config` also accepts a defconfig or a
  `.cfg` fragment, which list only deltas. There, a gate symbol the file never
  mentioned returned `not set in the shipped kernel config`, the verdict became
  `not_affected`, and the CVE left the dossier on evidence the tool had never
  actually checked.

  Provenance now travels with the data: `product.json` records
  `kernel_config_complete`, and the gate declines to conclude from absence
  unless the config is complete.

  **Re-run any dossier gated on a config fragment.** Verdicts produced from a
  full `.config` are unchanged.

### Fixed

- **Article 14(4) is a calendar month, measured from the submission.** The
  incident final-report deadline used `timedelta(days=30)` and counted from the
  72-hour notification *deadline*. Regulation (EEC, Euratom) No 1182/71 counts
  months to the day bearing the same number, and 14(4) runs from the submission:
  a notification filed on 31 January is due 28 February, where the old
  arithmetic said 2 March. Both errors moved the deadline later than the law
  does. Where no submission time was recorded the 72-hour deadline is still
  assumed, and the basis string now says so.
- **`cra24 doctor` no longer reports validation as available when it is not.**
  It checked that `jsonschema` imported and nothing else, while the validator
  also needs `referencing` and a `jsonschema` of at least 4.18. On a machine
  with the distribution's jsonschema 4.10 and no `referencing` — Ubuntu 24.04,
  for one — doctor printed a green line and the first `cra24 report` then died
  with a bare `ModuleNotFoundError`. The check now covers what the validator
  actually imports and names the missing piece.
- **Feed cache entry names are contained.** `root / feed / name` was built from
  identifiers that arrive from outside — a CVE typed on the command line, but
  also one read out of an SBOM or a cve-check summary — so an absolute name
  replaced the path and `../` walked out of the cache directory.
- **Feed responses are bounded**, at 512 MiB before and after decompression. A
  few hundred kilobytes of compressed zeros previously asked for as much memory
  as it liked, on a watch that runs unattended on an hourly timer.
- **A redirect from `https` to plaintext `http` is refused** rather than
  followed. The answers end up in a regulatory filing.
- A `429` or `5xx` on the final attempt no longer honours `Retry-After` before
  giving up anyway.

### Added

- **`cra24 verify --expect-head SHA256`.** Deleting records from the end of the
  ledger leaves a chain that is shorter and still internally consistent, so it
  verified clean — nothing inside a ledger can detect its own truncation. The
  head hash was always meant to be anchored somewhere you do not control; this
  makes that anchor checkable.
- **`cra24 doctor` reports how the evidence key was read** — hex or text, and
  how many bytes — in red below sixteen. A value that parses as hex is decoded
  as hex, so the passphrase `deadbeef` is four bytes rather than eight. That
  rule is unchanged, because changing it would invalidate every ledger already
  signed under it.
- `tests/test_repo_hygiene.py`, which the `licence headers` CI job has invoked
  since 0.2.0 without the file ever existing — so that job failed on every push
  while the check it stood for was not running. Enforces the SPDX header and
  copyright line on every source file, that each agrees with the licence
  `pyproject.toml` declares, and that no workflow runs a test path that is not
  there.

### Changed

- `Ledger.append()` reads the last record by seeking from the end instead of
  parsing the whole ledger, so appending no longer costs the length of the
  history. Ten years of hourly evidence was going to notice.
- `doctor`'s `jsonschema` line is now `validation`, since whether `jsonschema`
  imports was never the thing it was reporting.

---

## [0.3.0] — 2026-09-18

The release that answers the hardest input: *is this actually being exploited?*

### Added

- **Five feed clients**, all offline-capable, all using `urllib` from the
  standard library so the base package still has zero runtime dependencies.

  | Feed | Answers |
  | --- | --- |
  | CISA KEV | is this actively exploited — the Article 14(1) trigger |
  | ENISA EUVD | ENISA's own exploited list, plus the EUVD id for the SRP form |
  | EPSS | how likely exploitation is in 30 days, for ordering the queue |
  | OSV | which versions are affected and which one fixes it |
  | NVD | CVSS score and vector for the notification and final report |

- **`cra24 feeds sync` and `cra24 feeds status`.** Status names every host that
  would be contacted, how old each cached copy is, and — with `--terms` — the
  terms of use, all without opening a socket.
- **An on-disk cache that is a feature, not an optimisation.** Payloads are
  stored byte-identical to what the server sent, with the SHA-256 in a sidecar,
  so a cached artefact can be hashed and shown to be the file CISA published. A
  populated cache can be tarred up on a networked machine and copied to an
  air-gapped build machine, which is the normal case in this industry.
- **`--offline` everywhere**, refusing to open a socket and saying how old the
  cache is rather than pretending it is current.
- **`cra24 watch`** — poll the feeds against registered products and fire when
  something lands. Writes the dossier and starts the clock at the moment of
  detection, so what reaches you is a draft rather than an alert. Exits 1 on a
  reportable finding.
- **Notifiers**: stdout, `file:`, `webhook:` and `email:`, repeatable. SMTP
  credentials come from the environment, never a config file. A reportable alert
  carries `X-CRA24-Reportable: yes`.
- **A hardened systemd unit and timer** in `contrib/systemd/` — a oneshot on a
  timer rather than a long-lived daemon, with `RandomizedDelaySec` so that not
  every installation polls CISA on the hour.
- `docs/feeds.md` and `docs/watch.md`.

### Changed

- `triage()` takes an optional `enrichment`. Feed data fills arguments the caller
  did not supply and **never overrides one that was**: an explicit
  `--actively-exploited no` is a human decision and a feed does not overturn it.
- Every fact a feed supplied appears in the evidence trail with the feed named,
  so a dossier can show a verdict changed because CISA added the CVE this
  morning rather than because the tool changed its mind.
- `cra24 doctor` reports which feeds are cached and whether `NVD_API_KEY` is set.

### Fixed

- An overdue obligation rendered as "7h 51m overdue left". `_fmt_delta` already
  says "overdue"; the CLI no longer appends "left" to it. Nonsense wording at
  exactly the moment someone is reading carefully.

### Triage

- **A CVE listed in CISA KEV or ENISA's exploited list is now reportable without
  passing `--actively-exploited yes`.** Verdicts for such CVEs change from *not
  reportable, exploitation unknown* to *reportable*. Re-run anything you assessed
  before upgrading.
- **Absence from KEV is recorded as unknown, never as `False`.** KEV is
  conservative, curated and US-federal; absence means CISA has not confirmed
  exploitation, not that there is none. A customer reporting an attack starts the
  clock regardless.
- OSV version ranges now feed rule 1, which can move a verdict to `fixed` when
  the shipped version is at or past the advisory's fixed version.

---

## [0.2.0] — 2026-09-17

The release that turns a sketch into something you could file with.

### Added

- **Buildroot ingest** — `legal-info/manifest.csv` for the inventory,
  `pkg-stats.json` for CVE and CPE data, `<PKG>_IGNORE_CVES` read as a triage
  signal.
- **Kernel configuration gating** — `--gate CONFIG_SYM`. A CVE whose vulnerable
  code sits behind a symbol that is unset in the shipped `.config` is downgraded
  from `affected` to `not_affected` with the
  `vulnerable_code_not_in_execute_path` justification. Gating can only downgrade,
  never upgrade, and the absence of gating data is never read as "not gated".
- **A real triage engine** (`triage.py`) replacing the 0.1 status lookup. Every
  verdict carries a confidence level and the ordered list of rules that produced
  it, each with the file it read.
- **Yocto `CVE_STATUS` reason mapping** — the reason string, not just the
  patched/ignored/unpatched group, is read and mapped to the closed OpenVEX
  justification vocabulary. This is where most of the false-positive reduction
  lives.
- **CycloneDX `analysis.justification` mapping** — an SBOM that already carries
  triage decisions no longer loses them on ingest.
- **Advisory version-range matching** — `--fixed-version`, with introduced and
  last-affected bounds, using Debian ordering rules so
  `1.2.3+git0+abcdef1234-r0` compares correctly against `1.2.4`.
- **Schema validation on every emit.** CSAF 2.0 and OpenVEX 0.2.0 documents are
  validated against the vendored official schemas before they are written or
  recorded as evidence. `--no-validate` opts out.
- **Three reporting stages**, not one: `--stage early_warning | notification |
  final_report`, with later stages inheriting earlier fields.
- **Gap detection.** The dossier lists the mandatory fields that have no value,
  first, before anything else. `cra24 report` exits 6 when the dossier is written
  but not submittable, so a CI job can tell "not ready" from "crashed".
- **`cra24 init`** writes a configuration template with every field present.
- **`cra24 spec`** prints the SRP field set this release carries.
- **`cra24 doctor`** reports the installation: spec versions, bundled schemas,
  whether validation is available, whether evidence signing is configured.
- **Optional HMAC over evidence records** via `CRA24_EVIDENCE_KEY`, raising the
  bar from "an editor" to "someone who also has the key".
- **Dual licensing**: AGPL-3.0-only plus a commercial licence, with a CLA, a
  commercial licence template, and an SPDX header on every source file enforced
  by a test.

### Changed

- **The SRP field set moved out of code and into
  `src/cra24/data/srp-fields.json`**, versioned, with its sources and its known
  disagreements recorded. When ENISA moves the form, the fix is a data edit.
- **Product serialisation is deterministic.** `scanned_at` is stamped once at
  ingest instead of at save time, so saving the same inventory twice produces
  identical bytes and the evidence ledger does not record a spurious change.
- **Library code no longer calls `SystemExit`.** Everything raises from the
  `Cra24Error` hierarchy; only `cli.py` turns those into exit codes.
- **The evidence ledger** gained sequence numbers, artefact re-hashing on verify,
  and a `summary` view. Verification now reports every problem, not just the
  first.
- CSAF output models the component *inside* the product with a
  `default_component_of` relationship, carries purls in product identification
  helpers, and emits a flag or threat for every `known_not_affected` product.
- OpenVEX output emits components as subcomponents of the product, and always
  carries either a justification or an impact statement on `not_affected`.

### Fixed

- **A recipe whose packages ship under a different name is no longer dropped.**
  `cve-check` reports at recipe granularity (`linux-raspberrypi`) while image
  manifests list packages (`kernel-image-image`). The 0.1 ingest dropped the
  recipe because its own name was absent from the manifest, which silently
  removed every kernel CVE from the dossier. A recipe-to-package map built from
  `license.manifest` fixes it. *This is the most consequential bug fixed in this
  release; re-scan any 0.1 inventory.*
- Yocto `+gitAUTOINC+` version decoration is stripped correctly instead of
  leaving `AUTOINC+<hash>` attached to the version.
- `-v` is accepted both before and after the subcommand.

### Field spec

- Initial versioned spec, `2026-09-17`. Reconstructed from ENISA's SRP pages, the
  Commission's reporting guidance and two public field guides. Records two known
  disagreements: whether severity is mandatory at 24 hours, and whether the
  affected Member States field is "required" or "required if available".

---

## [0.1.0] — 2026-09-17

Initial sketch: Yocto and SBOM ingest, a flat SRP field list, CSAF and OpenVEX
emit, a hash-chained evidence ledger.

[1.0.1]: https://github.com/cra24/cra24/releases/tag/v1.0.1
[1.0.0]: https://github.com/cra24/cra24/releases/tag/v1.0.0
[0.4.0]: https://github.com/cra24/cra24/releases/tag/v0.4.0
[0.3.0]: https://github.com/cra24/cra24/releases/tag/v0.3.0
[0.2.0]: https://github.com/cra24/cra24/releases/tag/v0.2.0
[0.1.0]: https://github.com/cra24/cra24/releases/tag/v0.1.0
