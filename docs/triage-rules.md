# Triage rules

Every rule, in the order it runs, with what it can and cannot conclude.

This is the document to read before trusting a verdict, and the document to
update when you add a rule.

---

## The two safety properties

Everything below follows from these. If a change would violate either, it is
wrong regardless of how much noise it removes.

### 1. Rules may downgrade. They may not upgrade.

A rule may move a verdict from `affected` towards `not_affected` when it has
positive evidence the vulnerable code is unreachable. No rule may move a verdict
the other way on the strength of missing data.

Why the asymmetry: a false `affected` costs you an afternoon of triage. A false
`not_affected` is a published claim to your customers that their scanner is
wrong, about a vulnerability that is real. Those are not symmetrical mistakes and
the tool does not treat them as such.

### 2. "We looked and it is off" is not "we never looked"

`read_kernel_config` records an explicitly unset symbol as `"n"`. A symbol that
appears nowhere is absent from the dict. `_config_gate` returns `None` — no
conclusion — when there is no config data at all, and a conclusion only when it
has actually read the file.

Collapsing these two states is the single mistake that turns a triage tool into a
liability, because it makes "unknown" look like "safe".

---

## Rule 1 — Advisory version range

**Fires when** the caller supplies `advisory_fixed_version`,
`advisory_introduced` or `advisory_last_affected` — from `--fixed-version`, or in
a later release from a feed client.

**Concludes**

| Situation | Status | Justification | Confidence |
| --- | --- | --- | --- |
| Shipped version ≥ fixed version | `fixed` | — | high |
| Shipped version outside the range otherwise | `not_affected` | `vulnerable_code_not_present` | high |
| Shipped version inside the range | continue to rule 2 | — | — |

**Returns early** when conclusive. This is the most authoritative signal
available, because it comes from the people who fixed the bug, and it overrides
build metadata that may be stale.

**Range semantics** follow OSV: `introduced` inclusive, `fixed` exclusive,
`last_affected` inclusive. An advisory with no version data at all is an
unbounded range that matches everything, which is what it actually means.

**Version comparison** uses Debian ordering (`versions.py`), so
`1.2.3+git0+abcdef1234-r0` compares equal to `1.2.3`, `1.10` sorts above `1.9`,
`1.0~rc1` sorts below `1.0`, and an epoch beats everything. String comparison or
a strict PEP 440 parser gets these wrong quietly, and a quiet wrong answer here
is a CVE you did not report.

---

## Rule 2 — Build `CVE_STATUS` reason

**Fires when** the component has a `CveRecord` whose `detail` begins with a
reason string cra24 recognises.

This rule is where most of the false-positive reduction lives. Yocto records not
just *that* a CVE was handled but *why*, and the why maps onto the VEX
vocabulary. Most tools read only the coarse patched/ignored/unpatched group and
throw the reason away.

### Yocto `CVE_STATUS` reasons

| Reason | VEX status | Justification | Needs a human |
| --- | --- | --- | --- |
| `patched` | `fixed` | — | no |
| `backported-patch` | `fixed` | — | no |
| `cpe-stable-backport` | `fixed` | — | no |
| `fixed-version` | `fixed` | — | no |
| `not-applicable-config` | `not_affected` | `vulnerable_code_not_in_execute_path` | no |
| `not-applicable-platform` | `not_affected` | `vulnerable_code_not_present` | no |
| `not-applicable-os` | `not_affected` | `vulnerable_code_not_present` | no |
| `cpe-incorrect` | `not_affected` | `component_not_present` | **yes** |
| `disputed` | `under_investigation` | — | **yes** |
| `upstream-wontfix` | `affected` | — | **yes** |
| `ignored` | `not_affected` | — (impact statement) | **yes** |
| `unpatched` | `affected` | — | no |
| `vulnerable-investigating` | `under_investigation` | — | **yes** |

Notes on the judgement calls:

- **`cpe-incorrect` needs a human** because it asserts the scanner matched the
  wrong product entirely. That is often right and occasionally a way of making an
  inconvenient finding disappear. Publishing `component_not_present` on it
  unreviewed is a claim you may have to defend.
- **`disputed` is `under_investigation`, not `not_affected`.** Upstream disputing
  a CVE is an input to your decision, not your decision. You are the one placing
  the product on the market.
- **`upstream-wontfix` is `affected`.** Upstream declining to fix something does
  not make it unexploitable in your product. It makes it your problem.
- **Bare `ignored` gets an impact statement, not a justification**, because the
  reason was not recorded and a published `not_affected` needs something a reader
  can check.

### CycloneDX `analysis.justification`

An SBOM that already carries triage decisions should not lose them on ingest.
CycloneDX has nine justification values against OpenVEX's five, so several
collapse; the CycloneDX original is preserved in the finding's evidence text.

| CycloneDX | OpenVEX justification |
| --- | --- |
| `code_not_present` | `vulnerable_code_not_present` |
| `code_not_reachable` | `vulnerable_code_not_in_execute_path` |
| `requires_configuration` | `vulnerable_code_not_in_execute_path` |
| `requires_dependency` | `vulnerable_code_not_in_execute_path` |
| `requires_environment` | `vulnerable_code_not_in_execute_path` |
| `protected_by_compiler` | `inline_mitigations_already_exist` |
| `protected_at_runtime` | `inline_mitigations_already_exist` |
| `protected_at_perimeter` | `inline_mitigations_already_exist` |
| `protected_by_mitigating_control` | `inline_mitigations_already_exist` |

### Buildroot

Buildroot has no reason vocabulary. `<PKG>_IGNORE_CVES` produces
`ignored: listed in <PKG>_IGNORE_CVES`, which reaches rule 3 as a bare `ignored`
group and therefore always flags `requires_human`. That is the honest outcome:
the variable records a decision without recording its reason.

---

## Rule 3 — Build status group (fallback)

**Fires when** a `CveRecord` exists but carries no recognisable reason string.
This is every pre-scarthgap Yocto build, every Buildroot tree, and every SBOM
without an `analysis` block.

| Group | VEX status | Confidence | Needs a human |
| --- | --- | --- | --- |
| `patched` | `fixed` | low | **yes** |
| `ignored` | `not_affected` | low | **yes** |
| `unpatched` | `affected` | medium | no |
| `unknown` | `under_investigation` | low | **yes** |

**`patched` here yields `fixed` *and* `requires_human`.** A layer applied a
patch. Whether that patch addresses this CVE in this version is a question the
metadata does not answer, and the tool will not pretend otherwise. An impact
statement saying exactly that is attached to the output.

When a component ships but no scanner record mentions the CVE at all, the verdict
is `under_investigation` at low confidence with the finding
`not-in-build-metadata`. Silence is not evidence of absence.

---

## Rule 4 — Kernel configuration gate

**Fires when** gate symbols are supplied (`--gate`, or `component.config_symbols`)
**and** a kernel `.config` was read.

**Concludes**

| Config state | Effect |
| --- | --- |
| Any gate symbol is `=y` or `=m` | Records `vulnerable code built in`. No change to the status. |
| All gate symbols are unset or `n` | If status is `affected` → `not_affected` with `vulnerable_code_not_in_execute_path`, confidence high, `requires_human` cleared. |
| No symbols supplied, or no `.config` read | **Rule does not fire at all.** No finding, no change. |

This is the rule that earns the tool its keep on kernel CVEs, where a single
image can carry hundreds of findings for subsystems that were never compiled.

```
$ cra24 check --product product.json CVE-2024-1086 --gate NF_TABLES
  linux-raspberrypi 6.6.22 -> affected
    · kernel-config-gate: vulnerable code built in
      enabled in the shipped kernel config: CONFIG_NF_TABLES=m

$ cra24 check --product product.json CVE-2024-1086 --gate KSMBD
  linux-raspberrypi 6.6.22 -> not_affected
    justification: vulnerable_code_not_in_execute_path
    · kernel-config-gate: vulnerable code not built
      not set in the shipped kernel config: CONFIG_KSMBD
```

**Where gate symbols come from today:** you, on the command line, from reading
the advisory. **Where they will come from:** a curated mapping of CVE to gating
symbol, maintained as part of the feed described in
[roadmap.md](roadmap.md). That mapping is the defensible part of the business,
because it is the part that takes sustained human work rather than code.

**Its one limitation:** `=y` means the code is compiled in, not that it is
reachable from an attacker's position. A module compiled but never loaded, or a
subsystem behind a permission you always drop, is still shown as built in. cra24
will not claim otherwise on your behalf — if you have that knowledge, record it
as a justified `not_affected` yourself.

---

## Aggregation

A product's status is the worst of its components', by this precedence:

```
not_affected  <  fixed  <  under_investigation  <  affected
```

`requires_human` is true if it is true for any component.

## The reportability verdict

Separate from the VEX status, and the distinction matters more than anything else
in this document.

**Article 14(1) turns on active exploitation, not on severity.**

| Status | `actively_exploited` | Reportable | What cra24 says |
| --- | --- | --- | --- |
| `affected` | `True` | **yes** | The 24-hour clock is running. |
| `affected` | `False` | no | Fix it under Annex I Part II. Do not file an early warning. |
| `affected` | `None` | no | Establish exploitation before filing, and record when you did. |
| `fixed` | any | no | The shipped version is not vulnerable. Publish a VEX `fixed` statement. |
| `not_affected` | any | no | Publish the `not_affected` statement so your customers' scanners stop asking. |
| `under_investigation` | any | no | Do not file on a guess. Resolve before the 72-hour stage. |

A critical unpatched CVE with no exploitation evidence is not an Article 14
event. Filing one anyway wastes a CSIRT's attention and teaches your own team
that the alert means nothing.

The `None` case is deliberately unhelpful. cra24 does not know whether something
is being exploited, and a tool that guesses at the trigger for a legal obligation
would be worse than one that says it does not know.

---

## Reading the evidence

Every verdict carries its findings. On the command line:

```bash
cra24 check --product product.json CVE-2024-1086 -v
```

In the dossier, under **Why — the rules that fired**. In JSON, at
`components[].findings[]`:

```json
{
  "rule": "build-cve-status",
  "conclusion": "not-applicable-config -> not_affected",
  "evidence": "not-applicable-config: CONFIG_AWK is not enabled in this defconfig",
  "source": "yocto:cve-summary.json"
}
```

If a verdict ever surprises you, the findings say which rule produced it and
which file it read. If they do not, that is a bug worth reporting.
