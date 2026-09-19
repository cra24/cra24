# Command reference

Every command, flag and exit code.

```
cra24 [-v] [--json-logs] COMMAND [options]
```

`-v` and `--json-logs` work before or after the subcommand. `-v` gives info
logging, `-vv` gives debug.

---

## Exit codes

Stable, and meant to be depended on from CI.

| Code | Meaning | Raised by |
| --- | --- | --- |
| 0 | Success | — |
| 1 | Verification failed, or a deadline is overdue | `verify`, `clock` |
| 2 | A build tree or SBOM could not be read | `IngestError` |
| 3 | Configuration or arguments are wrong | `ConfigError` |
| 4 | A generated document failed schema validation | `ValidationError` |
| 5 | The evidence ledger is missing or unreadable | `EvidenceError` |
| 6 | **The dossier was written but is not submittable** | `DossierIncomplete` |
| 130 | Interrupted | — |

Code 6 is the one worth wiring up. It means cra24 did its job and *you* still
have fields to fill; the files exist and are usable. A CI job can tell that apart
from a crash.

---

## Inventory source flags

Shared by `scan`, `check` and `report`. Pass exactly one source.

| Flag | Source |
| --- | --- |
| `--build-dir DIR` | Yocto build directory — the one containing `tmp/` |
| `--machine NAME` | Restrict to one MACHINE under `tmp/deploy/images` |
| `--buildroot-dir DIR` | Buildroot output directory — the one containing `legal-info/` |
| `--sbom FILE` | CycloneDX or SPDX JSON |
| `--product FILE` | `product.json` from a previous `scan` |
| `--config FILE` | JSON or TOML identity file, overlaid on any of the above |
| `--kernel-config FILE` | Kernel `.config` for gating; auto-detected when omitted |

`--product` is the fast path. Scanning a large Yocto tree takes a moment;
scanning once and then running twenty `check` calls against the JSON does not.

---

## `cra24 init`

Write a configuration template.

```bash
cra24 init --out cra24.json --name AcmeGateway --product-version 2.4.0
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--out FILE` | `cra24.json` | Where to write |
| `--name NAME` | `MyProduct` | Product name |
| `--product-version V` | `1.0.0` | Product version |
| `--force` | off | Overwrite an existing file |

The generated file carries every field, plus notes on the three that cannot be
fixed after an incident: your coordinator CSIRT, your assigned representative's
EU Login account, and the Member States you sell into.

---

## `cra24 scan`

Read a build into `product.json`.

```bash
cra24 scan --build-dir ~/yocto/build --config cra24.json
cra24 scan --buildroot-dir ~/buildroot/output --config cra24.json --out gateway.json
```

| Flag | Meaning |
| --- | --- |
| `--out FILE` | Default `product.json` |
| `--include-unshipped` | Keep recipes that were built but not installed |

Output tells you what it found and what is still missing:

```
11 components -> product.json
  4 unpatched, 4 patched, 2 ignored, 0 unknown
  14 kernel config symbols read (available for gating)
```

**`--include-unshipped` is off for a reason.** Yocto's `cve-check` covers every
recipe built, including native tools that never reach the device. Counting those
overstates your attack surface and wastes your own triage time. Turn it on when
auditing the build itself rather than the product.

The written file is deterministic: scanning the same tree twice produces
identical bytes.

---

## `cra24 check`

Is this CVE actually in the shipped image, in code that runs?

```bash
cra24 check --product product.json CVE-2024-1086 -v
cra24 check --product product.json CVE-2024-1086 --gate NF_TABLES --json
```

| Flag | Meaning |
| --- | --- |
| `--actively-exploited yes\|no\|unknown` | Evidence of exploitation. Article 14(1) turns on this. |
| `--fixed-version V` | The version the advisory says fixes it |
| `--gate CONFIG_SYM[,...]` | Kernel symbols gating this CVE's code; repeatable |
| `--json` | Machine-readable output including the full evidence trail |
| `-v` | Show each finding's evidence text, not just its conclusion |

`--gate` accepts bare symbol names; `CONFIG_` is added if missing. A symbol that
is unset in the shipped `.config` downgrades `affected` to `not_affected`. A
symbol that is set changes nothing. See [triage-rules.md](triage-rules.md).

The `--json` output is the same structure that lands in the dossier under
`triage`, so anything you build against one works against the other.

---

## `cra24 report`

Emit the dossier, the advisory, the VEX document and the evidence record.

```bash
cra24 report --product product.json --config cra24.json CVE-2024-1086 \
  --aware-at 2026-09-17T08:30:00Z \
  --actively-exploited yes --severity high --malicious-intent yes \
  --summary "Exploited in the wild against internet-facing units."
```

### Required

| Flag | Meaning |
| --- | --- |
| `--aware-at ISO8601` | The moment you became aware. Starts all three clocks. |

### Stage and track

| Flag | Default | Values |
| --- | --- | --- |
| `--stage` | `early_warning` | `early_warning`, `notification`, `final_report` |
| `--track` | `vulnerability` | `vulnerability`, `incident` |

Later stages inherit every field from earlier ones, so `--stage notification`
carries the early warning's answers plus the four the 72-hour stage adds.

### Answering fields

| Flag | Meaning |
| --- | --- |
| `--severity low\|medium\|high\|critical\|unknown` | Your severity call |
| `--malicious-intent yes\|no\|unknown` | Mandatory on the incident track |
| `--cross-border yes\|no\|unknown` | Cross-border threat within the EU market |
| `--summary TEXT` | The few sentences a duty officer can act on |
| `--field KEY=VALUE` | Answer any field by key; repeatable |
| `--answers FILE` | JSON or TOML file of answers |

`--field` reaches every field in the spec, including ones with no dedicated flag:

```bash
--field attack_vector=network --field euvd_id=EUVD-2026-0451
```

Run `cra24 spec -v` for the keys.

For a real incident, put the long text in a file rather than on the command line:

```json
{
  "summary": "Exploited in the wild against internet-facing units since 15 September.",
  "initial_assessment": "Confirmed exploitation on two customer devices...",
  "corrective_measures": "Firmware 2.4.1 ships 2026-09-25 with the upstream patch.",
  "user_measures": "Restrict WAN-side management access until 2.4.1 is installed."
}
```

```bash
cra24 report … --stage notification --answers incident-answers.json
```

### Triage inputs

| Flag | Meaning |
| --- | --- |
| `--actively-exploited yes\|no\|unknown` | Drives the reportability verdict |
| `--fixed-version V` | Advisory's fixed version |
| `--gate CONFIG_SYM[,...]` | Kernel config gating; repeatable |

### Documents

| Flag | Default | Meaning |
| --- | --- | --- |
| `--tracking-id ID` | derived | CSAF advisory id |
| `--vex-id URL` | derived | OpenVEX `@id` |
| `--doc-version N` | 1 | Advisory and VEX version — **increment when you republish** |
| `--tlp RED\|AMBER\|GREEN\|WHITE` | `WHITE` | Traffic light marking on the advisory |
| `--no-validate` | off | Skip schema validation |
| `--measure-available ISO8601` | — | Starts the 14-day final report clock |

OpenVEX requires the version to increment whenever content changes. A document
republished at version 1 is one consumers cache and ignore.

### Output

| Flag | Default |
| --- | --- |
| `--out DIR` | `dossier` |
| `--evidence DIR` | `<out>/evidence` |

Five artefacts per run:

```
dossier/cve-2024-1086-early-warning.json    the structured dossier
dossier/cve-2024-1086-early-warning.md      the one you read at 2am
dossier/cve-2024-1086.csaf.json             for your customers
dossier/cve-2024-1086.openvex.json          for their scanners
dossier/evidence/ledger.jsonl               appended, not overwritten
```

### What it prints

Either `every mandatory field for this stage has a value`, or the list of what is
missing and exit code 6. Then the clocks, then the assessment.

---

## `cra24 clock`

The deadlines, without producing anything.

```bash
cra24 clock --aware-at 2026-09-17T08:30:00Z
cra24 clock --aware-at 2026-09-17T08:30:00Z --track incident --json
```

| Flag | Meaning |
| --- | --- |
| `--aware-at ISO8601` | Required |
| `--track vulnerability\|incident` | Default `vulnerability` |
| `--measure-available ISO8601` | Starts the 14-day final report clock |
| `--json` | Machine-readable |

**Exits 1 when any obligation is overdue**, so a cron job can alert without
parsing text:

```bash
cra24 clock --aware-at "$AWARE" || notify-me "CRA deadline passed"
```

---

## `cra24 verify`

Check the evidence hash chain.

```bash
cra24 verify dossier/evidence --summary
```

| Flag | Meaning |
| --- | --- |
| `--chain-only` | Verify the chain without re-hashing the artefacts |
| `--expect-head SHA256` | Require the chain to end at this head hash |
| `--summary` | Also print record count, head hash and timestamps |

Exit 0 if intact, 1 if not. `--chain-only` is for when the artefacts have been
archived elsewhere. See [evidence.md](evidence.md).

### Why `--expect-head` exists

A hash chain detects edits to what it contains. It cannot detect its own
truncation: delete the last few records and what remains is a shorter chain that
still links correctly end to end, so `verify` passes it.

The defence is to keep the head hash somewhere the person editing the ledger
does not control — a timestamp authority, a transparency log, or an email to
yourself. `--expect-head` is what turns that record into a check:

```bash
# when you file, keep the head somewhere else
cra24 verify dossier/evidence --summary | grep head

# later, prove the ledger still ends where it did
cra24 verify dossier/evidence --expect-head 261181ab8ef40ca8…
```

Without the anchor a truncated ledger reports `chain intact`. With it you get
exit 1 and a line saying the chain is intact but does not end where it should.

---

## `cra24 spec`

Show the SRP field spec this release carries.

```bash
cra24 spec                            # all stages plus the platform notes
cra24 spec --stage early_warning -v   # one stage, with the help text
cra24 spec --json                     # the raw spec
```

Markers: `*` required, `?` conditional, `=` derived by cra24, blank optional.

If this does not match the form you are looking at, please open a *field spec
drift* issue. See [srp-field-spec.md](srp-field-spec.md).

---

## `cra24 doctor`

What this installation knows and can do.

```
cra24 0.2.0
  python           3.11.15
  srp field spec   2026-09-17
  annex data       2026-09-17
  jsonschema       available
  evidence hmac    not set
```

Exits 1 if schema validation is unavailable. First thing to run when something
behaves unexpectedly, and the first thing to paste into a bug report.

---

## Environment variables

| Variable | Effect |
| --- | --- |
| `CRA24_EVIDENCE_KEY` | Hex or text key; adds an HMAC to every evidence record |
| `CRA24_LOG_JSON` | Set to anything but `0`/`false` to force JSON logs |
| `NO_COLOR` | Disable colour, per [no-color.org](https://no-color.org) |
| `CRA24_FORCE_COLOR` | Force colour when not writing to a terminal |

---

## Recipes

**Nightly drift check in CI, failing on an unpatched CVE in a KEV-style list:**

```bash
cra24 scan --build-dir "$BUILD" --config cra24.json --out product.json
for cve in $(cat watchlist.txt); do
  status=$(cra24 check --product product.json "$cve" --json | jq -r .status)
  [ "$status" = "affected" ] && echo "::error::$cve is affected" && fail=1
done
exit "${fail:-0}"
```

**Publish advisories for everything unpatched in a build:**

```bash
cra24 scan --build-dir "$BUILD" --config cra24.json --out product.json
jq -r '.components[] | .cves | to_entries[]
       | select(.value.status == "unpatched") | .key' product.json | sort -u |
while read -r cve; do
  cra24 report --product product.json --config cra24.json "$cve" \
    --aware-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --out "advisories/$cve" || true
done
```

**Watch a running clock:**

```bash
watch -n 60 cra24 clock --aware-at 2026-09-17T08:30:00Z
```
