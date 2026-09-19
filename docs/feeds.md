# Vulnerability feeds

## The promise, first

**cra24 makes no network call you did not ask for.** No telemetry, no update
checks, no background fetches. A feed host is contacted only when you run
`cra24 feeds sync` or pass `--feeds`, every client names the host it contacts,
and `--offline` refuses to open a socket at all.

```bash
cra24 feeds status --terms     # what would be contacted, and under what terms
```

The base package has **zero runtime dependencies**; the clients use `urllib`
from the standard library. A security review of a tool with no dependency tree
is a short conversation, and in this industry that matters more than the
ergonomics of `requests`.

---

## What each feed is for

| Feed | Host | Answers | Default freshness |
| --- | --- | --- | --- |
| **KEV** | `www.cisa.gov` | Is this being actively exploited? | 6 hours |
| **EUVD** | `euvdservices.enisa.europa.eu` | ENISA's own exploited list, and the EUVD id | 12 hours |
| **EPSS** | `epss.cyentia.com` | How likely is exploitation in 30 days? | 24 hours |
| **OSV** | `api.osv.dev` | Which versions are affected, what fixes it | per query |
| **NVD** | `services.nvd.nist.gov` | CVSS score and vector | per CVE |

KEV and EUVD answer the Article 14(1) trigger. OSV feeds rule 1 of the triage
engine. EPSS orders your queue. NVD supplies a severity figure you can defend.

---

## The judgement call at the centre of this

```
presence in KEV  →  actively_exploited = True
absence from KEV →  actively_exploited = unknown, never False
```

KEV is a US federal remediation mandate, conservative and curated. CISA adds an
entry when it has **confirmed** exploitation. So presence is strong evidence and
absence is weak evidence — it means CISA has not confirmed exploitation, which is
not the same as confirming there is none.

A customer telling you your product is being attacked starts the 24-hour clock
whether or not CISA has heard of it. cra24 will not report `actively_exploited:
false` on the strength of a feed's silence, and it says so in the evidence:

```
cisa-kev: not listed
  absence is not evidence of no exploitation; KEV is conservative and
  US-federal, so this leaves the Article 14(1) trigger unknown
```

**EPSS is never treated as evidence of exploitation.** It is a prediction;
Article 14(1) turns on an observed fact. A 0.97 EPSS score is a reason to look at
something first thing tomorrow, not a reason to file.

---

## Feeds never override you

Feed data fills the arguments `triage()` already takes. It does not overturn a
decision you made:

```bash
# KEV says exploited; you have looked and disagree. You win.
cra24 check --product product.json CVE-2024-1086 --actively-exploited no
```

Every fact a feed supplied lands in the evidence trail with the feed named, so a
dossier can show that a status changed because CISA added the CVE this morning,
rather than because the tool changed its mind:

```
· feed:cisa-kev: actively exploited
  listed in CISA KEV on 2024-05-30; as Linux Kernel
· feed:osv: fixed in 6.6.25
  from CVE-2024-1086
```

---

## Using them

### Sync

```bash
cra24 feeds sync                  # fetch what is stale
cra24 feeds sync --only kev,euvd  # just the exploitation feeds
cra24 feeds sync --force          # ignore freshness
cra24 feeds status --json         # for a monitoring check
```

Bulk feeds (KEV, EPSS, EUVD) are downloaded whole. OSV and NVD are queried per
package and per CVE, so they populate their cache as you use them.

Conditional requests are used where the server supports them: an unchanged feed
costs one 304 rather than a re-download.

### In a command

```bash
# default: use an existing cache, never open a socket
cra24 check --product product.json CVE-2024-1086

# allow fetching if the cache is stale
cra24 check --product product.json CVE-2024-1086 --feeds

# a subset
cra24 check --product product.json CVE-2024-1086 --feeds kev,osv

# never open a socket, even with --feeds
cra24 check --product product.json CVE-2024-1086 --feeds --offline

# ignore feed data entirely, even a cached copy
cra24 check --product product.json CVE-2024-1086 --no-feeds
```

The default is deliberate. Reading a file you already have is not a network call,
and a triage run that silently reached out to the internet would be one you could
not reproduce later.

---

## The air-gapped build machine

This is the normal case in embedded, not an edge case, and it is why the cache is
a feature rather than an optimisation.

On a machine with a network:

```bash
cra24 feeds sync --force
tar -czf cra24-cache.tar.gz .cra24-cache
```

On the build machine:

```bash
tar -xzf cra24-cache.tar.gz -C /var/lib/cra24
export CRA24_CACHE_DIR=/var/lib/cra24/.cra24-cache
cra24 check --product product.json CVE-2024-1086 --offline
```

cra24 will tell you how old the cache is rather than pretending it is current:

```
[ok] kev    18.4h ago      1247 records
```

The payload is stored **byte-identical to what the server sent**, with the
SHA-256 in a sidecar `.meta` file. So you can hash a cached artefact and show an
auditor it is the file CISA published, and you can record that hash in the
evidence ledger alongside the dossier it informed.

---

## NVD rate limits

Roughly 5 requests per rolling 30 seconds without a key, 50 with one. The client
spaces requests a little slower than the stated ceiling, because being
rate-limited mid-incident is worse than being slow.

```bash
export NVD_API_KEY=...     # free from nvd.nist.gov
cra24 feeds status          # doctor and status both show whether a key is set
```

---

## Terms of use

`cra24 feeds status --terms` prints these. Summarised:

| Feed | Terms |
| --- | --- |
| KEV | US Government work, generally free of copyright in the US |
| EPSS | Free for any use including commercial, with attribution to FIRST |
| OSV | Schema and service Apache-2.0; records carry their source database's terms |
| NVD | US Government work; NIST asks that you not imply endorsement |
| EUVD | ENISA; EU institution material, generally reusable under Decision 2011/833/EU with attribution |

cra24 caches this data locally for your own use. **Redistributing a cache is
a different question** — check each feed's current terms before publishing one,
particularly for OSV, where individual records carry their upstream database's
licence rather than OSV's.

---

## What is deliberately not done here

**No scanner is bundled.** cra24 reads what `cve-check` and `pkg-stats` already
wrote. Building a fifth vulnerability scanner would be effort spent where the
problem is already solved.

**NVD's CPE data is not used for affectedness.** NVD's configurations are coarse
for embedded components — a CPE for `linux_kernel` matches every kernel ever
shipped — and treating that as "you are affected" is how a triage tool produces
five hundred findings for one image. OSV's version ranges answer that properly.

**No feed can make a product reportable on its own.** It still has to be in your
image, in code that is compiled in. The feeds answer *is it exploited*; the build
tree answers *is it yours*; both have to be true.
