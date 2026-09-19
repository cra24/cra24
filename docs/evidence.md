# The evidence ledger

## The problem it solves

CRA technical documentation has to be kept for **ten years, or for the support
period, whichever is longer**. For an industrial gateway with a fifteen-year
service life, that is a document you will be asked about by someone who has never
met you, about a build made by someone who has left.

What matters at that point is not the dossier alone. It is **proof of which
inputs produced it**, and that nobody has quietly edited it since.

A folder of JSON files does not provide that. A git repository nearly does, but a
repository can be rewritten and its history is only as trustworthy as the
account that pushed it. What you want is something cheap, offline, and awkward to
forge.

## What it is

An append-only JSONL file where each record carries the SHA-256 of every artefact
written at that moment, plus the hash of the previous record.

```jsonl
{"artefacts":{"dossier/cve-2024-1086.csaf.json":"a3f1…"},"event":"article-14-early_warning","meta":{"aware_at":"2026-09-17T08:30:00Z","cve":"CVE-2024-1086","product":"AcmeGateway","spec_version":"2026-09-17","tool_version":"0.2.0","triage_status":"affected","validated":true},"prev":"0000…","recorded_at":"2026-09-17T20:44:51+00:00","seq":0}
{"artefacts":{"dossier/cve-2024-1086-notification.md":"7b2c…"},"event":"article-14-notification","meta":{…},"prev":"e502…","recorded_at":"2026-09-19T11:02:13+00:00","seq":1}
```

Changing any artefact, or any earlier record, breaks the chain at a point you can
name.

```bash
$ cra24 verify dossier/evidence --summary
  chain intact over 2 records
  head e5029ae3adbdda18…
  no HMAC key set (CRA24_EVIDENCE_KEY unset)
```

```bash
$ cra24 verify dossier/evidence     # after someone edited an advisory
  record 0: cve-2024-1086.csaf.json has changed since it was recorded
$ echo $?
1
```

## What it proves, and what it does not

**It is tamper-evident.** You can show an auditor that the chain is intact, that
a given file is byte-for-byte the one cra24 wrote, and that the sequence of
records has not been reordered or thinned.

**It is not a trusted timestamp.** The recorded times come from the machine that
ran the tool. Nothing stops someone with filesystem access from regenerating the
whole chain with different dates. If you need to prove to a third party *when*
something existed, you must anchor it — see below.

**It is not a substitute for keeping the artefacts.** The ledger records hashes.
If you delete the dossier, verification will tell you the artefacts are missing,
which is correct but not helpful. Keep both.

## Anchoring, if you need third-party proof

The ledger's head hash is a 64-character string that commits to everything before
it. Publishing that head somewhere you do not control converts "I say this
existed" into "this existed by then".

In rough order of effort:

1. **Email the head hash to yourself**, or to your notary or counsel, after each
   filing. A mail server's received timestamp is evidence, and this takes ten
   seconds.
2. **Commit the ledger to a repository your organisation does not administer**,
   or one with protected history and signed tags.
3. **An RFC 3161 timestamp authority.** `openssl ts` against a public TSA gives
   you a signed token over the head. This is the option that survives a hostile
   reading.
4. **A transparency log.** More machinery than most manufacturers need, but it is
   the same idea at scale.

```bash
# the head, for whichever of the above you choose
cra24 verify dossier/evidence --summary | python3 -c \
  "import sys,json; print(json.loads(sys.stdin.read().split(chr(10)+chr(10))[1])['head'])"
```

## Optional HMAC

Setting `CRA24_EVIDENCE_KEY` adds an HMAC-SHA256 over every record.

```bash
export CRA24_EVIDENCE_KEY=$(openssl rand -hex 32)
cra24 report --product product.json CVE-2024-1086 --aware-at …
cra24 verify dossier/evidence
#   chain intact over 1 record
#   head 1f6faa4c2247717b…
#   HMAC verified
```

This raises the bar from "someone with an editor" to "someone with an editor
**and** the key".

**Keep the key off the build machine.** A signing key stored next to the thing it
signs protects nothing, and it is worth being honest that an HMAC is symmetric —
anyone who can verify can also forge. If you need signatures a third party can
check without being able to produce them, that is a public-key signature, and it
is on the roadmap rather than in this release.

Verification is explicit about the states that could otherwise be misread:

| Situation | What `verify` says |
| --- | --- |
| Key set, HMACs present and correct | `HMAC verified` |
| Key set, a record has no HMAC | `record N: no HMAC, but a key is configured` |
| Key set, HMAC wrong | `record N: HMAC does not match` |
| No key, records carry HMACs | `record N: carries an HMAC but no key is configured` |
| No key, no HMACs | `no HMAC key set (CRA24_EVIDENCE_KEY unset)` |

That fourth row matters: a ledger that was signed and is now being verified
without the key must not quietly pass.

## What goes into a record

| Field | Meaning |
| --- | --- |
| `seq` | Position in the chain, from 0 |
| `recorded_at` | When the record was appended, from the local clock |
| `event` | What produced it, e.g. `article-14-early_warning` |
| `prev` | SHA-256 of the previous record's canonical form; zeros for the first |
| `artefacts` | Path → SHA-256 for every file written at that moment |
| `meta` | CVE, product, product version, awareness time, track, triage status, cra24 version, field spec version, whether the documents were schema-validated |
| `hmac` | Present only when a key was configured |

The `meta` block is what makes the record useful years later. `spec_version`
records which field set the dossier was built against, and `tool_version` records
which triage rules ran — so a verdict can be explained even after both have
moved on.

Records are canonicalised with sorted keys and no whitespace before hashing, so
the chain does not depend on formatting.

## Practical notes

**Use one ledger per product, not one per CVE.** The chain is more useful the
longer it is, and a per-CVE ledger tells you nothing about ordering across
events.

```bash
cra24 report --product gateway.json CVE-2024-1086 \
  --aware-at … --out dossiers/cve-2024-1086 --evidence evidence/gateway
```

**Re-running `report` appends rather than overwrites.** A draft dossier and the
corrected one are both in the chain, in order. That is the intent: showing that
you filed at 23:00 with what you knew, and corrected at 09:00, is a better story
than a single file that appears to have sprung into existence complete.

**Do not commit dossiers to a public repository.** `.gitignore` excludes
`product.json`, `dossier/` and `evidence/` by default. They contain an
unpatched-vulnerability inventory of a shipping product.

**Verification is offline.** No network, no service, no account. It works in
2034 with nothing but the files and a Python interpreter — which is the reason
the format is boring JSONL rather than anything cleverer.

## Using it from Python

```python
from cra24.evidence import Ledger

ledger = Ledger("evidence/gateway")
ledger.append("custom-event", ["some/file.pdf"], meta={"note": "supplier attestation"})

ok, messages = ledger.verify()
ledger.summary()   # records, head, first and last timestamps, event names
```

`verify(check_files=False)` checks the chain without re-hashing artefacts, which
is what you want when the artefacts have been archived elsewhere.
