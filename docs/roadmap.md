# Roadmap

Where this is going, and why in this order.

The ordering is not arbitrary. Each step makes the next one cheap, and the
sequence is chosen so that the open-source tool is genuinely useful at every
stage rather than a crippled demo waiting for a paid feature.

---

## Shipped — 0.3.0

Five feed clients (CISA KEV, ENISA EUVD, EPSS, OSV, NVD), all offline-capable
and all using only the standard library. An on-disk cache built for air-gapped
build machines. Watch mode with notifiers, state that fires once, an awareness
timestamp that never moves, and a hardened systemd unit.

The design constraints set out below were kept: opt-in, every host named,
cacheable, and feed data never overrides a human decision.

## Shipped — 0.2.0

Yocto and Buildroot ingest, CycloneDX and SPDX ingest, kernel configuration
gating, the triage engine with a full evidence trail, schema-validated CSAF and
OpenVEX, hash-chained evidence, three reporting stages, the versioned SRP field
spec, and the dual-licence scaffolding.

This is the part that has to be free and good. An embedded engineer who runs
`cra24 check` and gets a defensible answer in ten seconds is the only marketing
this project will ever do.

---

## Delivered in 0.3 — Feed clients

**The problem it solved:** Article 14(1) turns on *active exploitation*. cra24
refused to guess and asked you to assert it. Honest, but it left the hardest
input to a human at the worst possible moment.

**What landed:**

| Feed | What it answers | Notes |
| --- | --- | --- |
| **CISA KEV** | Is this being exploited in the wild? | The closest public proxy for the Article 14(1) trigger. Small, stable, easy to cache. |
| **EPSS** | How likely is exploitation in the next 30 days? | For prioritising the queue, not for the reporting decision. |
| **OSV** | Which versions are affected, and what fixes it? | Fills `advisory_fixed_version`, `introduced`, `last_affected` — rule 1 of the triage engine already takes these. |
| **NVD** | CVSS, CPE, references | Rate-limited; cache aggressively. |
| **EUVD** | ENISA's own identifiers | The SRP has an EUVD field. Nobody is filling it yet. |

**Design constraints, written down before the code and kept:**

- Opt-in. cra24 makes no network call you did not ask for.
- Every client names the host it contacts, and `cra24 feeds status` prints them
  all without contacting any of them.
- A local cache under `.cra24-cache/`, so a build machine behind a firewall can
  be handed a cache directory rather than an internet connection. The payload is
  stored byte-identical to what the server sent, so it can be hashed into the
  evidence ledger.
- Feed data never overrides your own triage. It fills the arguments `triage()`
  already takes, and every finding records which feed said what.
- Zero new runtime dependencies. `urllib` from the standard library.

**Why it was small:** the triage engine had been built to take these inputs.
No new middle layer, only `feeds/`.

The one judgement call worth re-reading: **absence from KEV is recorded as
unknown, never as "not exploited"**. See [feeds.md](feeds.md).

---

## Delivered in 0.3 — Watch mode

```bash
cra24 watch --products products/ --once --notify webhook:https://…
```

A pass over registered `product.json` files, polling the feeds, calling the same
`triage()`, firing when something lands. Ships with a hardened systemd unit and
timer.

**What "firing" means:** it writes the pre-filled dossier, starts the clock at
the moment of detection, and notifies. The value is not the alert; every scanner
sends alerts. The value is that the thing waiting in your inbox at 7am is a
dossier with four fields left to fill and a clock that started at 03:14.

Three properties that took most of the work, and are what make it usable rather
than merely functional: an alert fires **once**; the awareness timestamp is
**never rewritten** once set, because Article 14 runs from awareness and a tool
that refreshed it would understate how long you have known; and one bad product
file or dead webhook does not stop the pass.

**Still to come:** the local dashboard. It will ship *inside* the watcher rather
than as a separate service — device families, open CVEs, running clocks, dossier
status. One binary, one port, no database to operate.

---

## 0.4 — CI integration

A GitHub Action and a GitLab template, **deliberately Apache-2.0 rather than
AGPL**. They are clients; making them permissive removes every excuse not to
adopt them, and they drag the engine into build pipelines behind them.

```yaml
- uses: cra24/scan-action@v1
  with:
    build-dir: build/
    config: cra24.json
    fail-on: kev-affected
```

Fails the build when a KEV-listed CVE is unpatched in the image. Uploads the
SBOM, the VEX document and the dossier as artefacts. This is the cheapest
distribution channel that exists for a tool like this.

---

## 1.0 — The service

The same engine behind a REST API, multi-tenant, self-hostable, EU-hosted.
Customers upload a `product.json` per device family; the service runs the watch
and mails the pre-filled dossier when something lands.

**"Self-hostable, or EU-hosted by us"** is the differentiator against Vigiles and
the Lynx-owned tooling. An embedded manufacturer being asked to upload a complete
inventory of their firmware's unpatched vulnerabilities to a US-owned SaaS has a
reasonable objection, and nobody is currently answering it.

This is where the AGPL does its work: a competitor can run the service, and if
they do, their users are entitled to the source of what they are running.

---

## The moat — a curated VEX feed

Everything above is code, and code gets copied. This is the part that does not.

Triage decisions on the top few hundred components that appear in embedded Linux
images — busybox, openssl, the kernel, dropbear, dnsmasq, libcurl, zlib, glibc,
musl — published as OpenVEX. Plus, and this is the valuable half, **the mapping
of kernel CVEs to the config symbols that gate them**, which is what makes rule 4
of the triage engine work without a human reading each advisory.

Why it is defensible:

- It takes sustained human work, not a clever algorithm.
- It compounds: every decision made once serves every subscriber forever.
- It is a subscription by nature — a feed that stops updating stops being worth
  anything within weeks.
- Correctness matters more than completeness, so a fast follower cannot catch up
  by scraping.

**The precedent is exact.** Timesys built Vigiles as open-source Yocto and
Buildroot layers feeding a paid curated CVE database, and sold it into Lynx. The
model works. The gap is that it is enterprise-priced, and the shop building 2,000
units a year — which is most of this industry — is not served by anyone.

---

## What is deliberately not on this roadmap

**An SBOM generator.** That space is crowded and the tools are good. cra24 reads
SBOMs; it does not compete to produce them.

**A vulnerability scanner.** cra24 reads what `cve-check` and `pkg-stats` already
wrote. Building a fifth scanner would be work spent where the problem is already
solved.

**Automated submission to the SRP.** The platform has no API, and even if it
gains one, a filing under Article 14 is a statement by a legal person. That
person presses the button. Automating up to the button is the whole design.

**Anything that claims to make you compliant.** cra24 organises evidence and
drafts documents. The claim that a tool makes you compliant is false for every
tool, and making it would cost more trust than it could ever buy.

---

## Version support

Until 1.0, security fixes land on the latest minor release only. After 1.0, the
intent is one year of fixes on the previous minor — which, for a tool aimed at
manufacturers with ten-year documentation duties, is the minimum that would be
honest to promise.
