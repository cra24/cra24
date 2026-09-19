# cra24

**Turn an embedded Linux build tree into a CRA Article 14 dossier before the
24-hour clock runs out.**

[![licence: AGPL-3.0-only](https://img.shields.io/badge/licence-AGPL--3.0--only-blue.svg)](LICENSE)
[![commercial licence available](https://img.shields.io/badge/commercial%20licence-available-green.svg)](LICENSING.md)
[![python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

> **Unofficial.** Not affiliated with, endorsed by, or validated by ENISA, the
> European Commission, any national CSIRT, any market surveillance authority, or
> any notified body. cra24 organises evidence your build already produced and
> drafts documents for a human to review. It certifies nothing and submits
> nothing.

---

## Why this exists

ENISA's Single Reporting Platform went live on **11 September 2026**, the day
reporting obligations started binding manufacturers, and it shipped **without an
API**. So the 24-hour early warning is a human filling in a web form, in English,
at whatever hour the news arrives.

Everyone else is building SBOM generators. The unserved job is the one *after*
the SBOM:

1. Given a CVE, is it actually in the image I ship — not merely in a recipe I built?
2. Is the vulnerable code even compiled in?
3. What do I put in the form, right now, in the platform's own field order?
4. What do I hand my customers, machine-readably, so their scanners stop asking?
5. How do I prove, in eight years, that the dossier came from the build I say it did?

cra24 answers those five and nothing else.

### Three clocks, from the moment you become aware

| Stage | Vulnerability, Art. 14(1)–(2) | Severe incident, Art. 14(3)–(4) |
| --- | --- | --- |
| Early warning | 24 hours | 24 hours |
| Notification with initial assessment | 72 hours | 72 hours |
| Final report | 14 days after a corrective or mitigating measure is available | 1 month after the 72-hour notification |

Two traps worth knowing before you need them:

- The platform's own 72-hour counter has been reported to run from **submission
  of the early warning** rather than from the moment you became **aware**. Those
  are different instants and the second one is the legal test. `cra24 clock` uses
  awareness.
- There is **no platform counter at all** for the vulnerability final report,
  because the deadline depends on when your fix ships. Nothing will remind you.

---

## Quickstart

```bash
pip install 'cra24[validate]'

# 0. one-time: your identity, Member States, coordinator CSIRT
cra24 init --out cra24.json && $EDITOR cra24.json

# 1. read a build you already ran — no bitbake, no rebuild
cra24 scan --build-dir /path/to/yocto/build --config cra24.json

# 2. is this CVE actually in the shipped image, in code that runs?
cra24 check --product product.json CVE-2024-1086 -v

# 3. the dossier: portal fields, CSAF advisory, OpenVEX, evidence record
cra24 report --product product.json --config cra24.json CVE-2024-1086 \
  --aware-at 2026-09-17T08:30:00Z \
  --actively-exploited yes --severity high --malicious-intent yes \
  --summary "Exploited in the wild against internet-facing units."

# 4. let the feeds answer the hardest question for you
cra24 feeds sync
cra24 check --product product.json CVE-2024-1086      # now knows it is in CISA KEV

# 5. watch, so the next one finds you
cra24 watch --products products/ --once --notify email:psirt@example.com

# 6. just the clocks
cra24 clock --aware-at 2026-09-17T08:30:00Z

# 7. the ten-year question: has the evidence been tampered with?
cra24 verify dossier/evidence --summary
```

Try it against the fixture that ships with the repo:

```bash
cra24 check --build-dir tests/fixtures/yocto-build \
            --config tests/fixtures/demo-config.json CVE-2024-1086 -v
```

---

## What it produces

| File | For whom | What it is |
| --- | --- | --- |
| `*-early-warning.md` | you, at 2am | The portal's fields, filled, in order, with **the unanswered mandatory ones listed first**. This is the one you read. |
| `*-early-warning.json` | your tooling | The same, structured, with the full triage evidence attached. |
| `*.csaf.json` | your customers | CSAF 2.0 advisory in the VEX profile. Validated against the OASIS schema on every emit. |
| `*.openvex.json` | their scanners | OpenVEX 0.2.0. Validated too. |
| `evidence/ledger.jsonl` | the auditor in 2034 | Hash-chained record of every artefact and the inputs that produced it. |

---

## What makes the triage worth trusting

Most tools turn "the scanner said CVE-X" into "you are affected". cra24 refuses to
do that, and shows its work instead.

**Every conclusion carries its evidence.** A verdict is never just a status; it is
a status, a confidence level, and the ordered list of rules that fired with the
file each one read:

```
CVE-2023-42364 in AcmeGateway 2.4.0: not_affected

  busybox 1.36.1 -> not_affected
    justification: vulnerable_code_not_in_execute_path
    · build-cve-status: not-applicable-config -> not_affected
      not-applicable-config: CONFIG_AWK is not enabled in this defconfig
```

**`patched` is evidence, not proof.** When a layer reports a patch but records no
reason, cra24 emits `fixed` *and* flags `requires_human`, rather than a quiet
all-clear.

**Kernel config gating can only downgrade, never upgrade.** A CVE in a driver you
never compiled is not your CVE — but the absence of gating data is never read as
"not gated". That asymmetry is deliberate; the opposite one is how a triage tool
becomes a liability.

**Justifications come from the closed OpenVEX vocabulary**, never free text,
because a free-text justification is one a downstream scanner cannot act on. The
Yocto `CVE_STATUS` reason strings are mapped to it explicitly in
[`triage.py`](src/cra24/triage.py), and that table is where most of the
false-positive reduction actually lives.

---

## The field spec is data, not code

`src/cra24/data/srp-fields.json` carries the SRP field set, versioned, with its
sources and — importantly — its **known disagreements**, where public guides
contradict each other about what is mandatory at 24 hours.

When ENISA moves the form, and it will, the fix is a data edit. You can patch it
yourself without waiting for a release:

```bash
cra24 spec --stage early_warning -v
```

If you find a drift, please open a *field spec drift* issue. That file should be
the most accurate public description of the form that exists, and it only gets
there if people report what they see.

---

## Documentation

| Document | What it covers |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | The canonical-model design, and how to add an ingester or emitter |
| [docs/feeds.md](docs/feeds.md) | The five feeds, what each answers, and the air-gapped workflow |
| [docs/watch.md](docs/watch.md) | Watch mode, notifiers, and the systemd unit |
| [docs/article-14.md](docs/article-14.md) | The regulation mapped to the code, clause by clause |
| [docs/triage-rules.md](docs/triage-rules.md) | Every rule, in order, with what it can and cannot conclude |
| [docs/srp-field-spec.md](docs/srp-field-spec.md) | The field spec, its sources, and how to correct it |
| [docs/evidence.md](docs/evidence.md) | What the ledger proves, what it does not, and how to anchor it |
| [docs/cli.md](docs/cli.md) | Every command, flag and exit code |
| [docs/roadmap.md](docs/roadmap.md) | Where this is going and why |
| [LICENSING.md](LICENSING.md) | The dual-licence model in plain words |

---

## Licensing, briefly

cra24 is **dual-licensed: AGPL-3.0-only, or a commercial licence.**

**Using cra24 to produce your own compliance dossiers is free, forever, for any
company of any size.** Running the CLI on your build is not distribution and the
AGPL asks nothing of you.

You need a [commercial licence](LICENSING.md#buying-a-commercial-licence) only if you **ship cra24
inside a product you distribute**, or **offer it to others over a network**, and
do not want to publish your source. That is the entire business model, stated
plainly. See [LICENSING.md](LICENSING.md).

Contributions require a [CLA](CLA.md), which is what makes the dual licence
possible. You keep your copyright; the project undertakes in writing that your
contribution stays available under the AGPL.

---

## Feeds, and the question they answer

Article 14(1) turns on **active exploitation**, not severity. That is the hardest
input to supply at 3am, and `0.3.0` supplies it:

```
CVE-2024-1086 in AcmeGateway 2.4.0: affected

  linux-raspberrypi 6.6.22 -> affected
    · advisory-version-range: within the affected range
      6.6.22 is inside [introduced 3.15, fixed 6.6.25]
    · feed:cisa-kev: actively exploited
      listed in CISA KEV on 2024-05-30
    · feed:osv: fixed in 6.6.25

REPORTABLE — Article 14(1): the vulnerability is contained in the product
and is actively exploited. The 24-hour clock is running.
```

Five feeds: **CISA KEV** and **ENISA EUVD** for exploitation, **OSV** for version
ranges, **NVD** for CVSS, **EPSS** for ordering your queue.

Three commitments they keep:

- **cra24 makes no network call you did not ask for.** No telemetry, no update
  checks. `cra24 feeds status` names every host that would be contacted, without
  contacting it.
- **Offline is a first-class mode.** Sync a cache where there is a network, tar
  it, copy it to the build machine. `--offline` never opens a socket and tells
  you how old the cache is instead of pretending it is current.
- **Absence from KEV is recorded as *unknown*, never as *not exploited*.** KEV is
  conservative and US-federal; a customer reporting an attack starts your clock
  whether or not CISA has heard of it.

And feeds never overturn you — `--actively-exploited no` wins over KEV, because
that is a human decision.

See [docs/feeds.md](docs/feeds.md).

## Watch mode

```bash
cra24 watch --products products/ --once --notify email:psirt@example.com
```

The thing waiting for you at 07:00 is not an alert. It is a **dossier with four
fields left to fill and a clock that started at 03:14**.

It fires once per finding, never rewrites an awareness timestamp it has already
set, and survives a bad product file or a dead webhook. Exit code 1 means a
reportable finding, so cron can act on it without parsing text. A hardened
systemd unit and timer are in `contrib/systemd/`.

See [docs/watch.md](docs/watch.md).

## Status and roadmap

`0.3.0` — everything in `0.2.0`, plus five offline-capable feed clients, watch
mode, notifiers and a systemd unit.

`0.2.0` — Yocto and Buildroot ingest, SBOM ingest, kernel config gating, the
triage engine, schema-validated CSAF and OpenVEX, hash-chained evidence.

Next, in order:

1. **CI integration** — a GitHub Action and a GitLab template, deliberately
   Apache-2.0 rather than AGPL, because they are clients and permissive removes
   every excuse not to adopt them.
2. **Service and dashboard** — the same engine behind a REST API and a local UI,
   self-hostable, EU-hosted.
3. **Curated VEX feed** — triage decisions on the top few hundred embedded
   components, published as OpenVEX, plus the mapping of kernel CVEs to the
   config symbols that gate them. Timesys built exactly this and sold it to Lynx;
   nobody serves the shop building 2,000 units a year.

See [docs/roadmap.md](docs/roadmap.md).

---

## Caveats worth keeping in the README

- The field spec mirrors the published required set. **Verify it against ENISA's
  AR User Manual for your own account.** The form is young.
- **Registration cannot be done retroactively.** Named representatives need
  working EU Login accounts with MFA *before* an incident, and the coordinator
  CSIRT is chosen once — selecting the wrong one invalidates a notification.
- `patched` in build metadata means a layer applied a patch, not that you are
  safe. Keep the human in the loop. cra24 is built to make that easy, not to
  remove it.
- Article 14(1) turns on **active exploitation**, not on severity. An unpatched
  critical CVE with no exploitation evidence is a thing to fix under Annex I
  Part II, not a thing to file an early warning about. cra24 will tell you so.
