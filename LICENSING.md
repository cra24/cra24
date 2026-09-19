# Licensing

cra24 is dual-licensed. You choose which licence you take it under.

| | Open source | Commercial |
| --- | --- | --- |
| Licence | GNU AGPL-3.0-only | cra24 Commercial Licence |
| Price | Free | Paid, per agreement |
| Source disclosure | Required, including over a network | Not required |
| Suitable for | Internal use, research, AGPL projects, evaluation | Embedding in a proprietary product, or offering cra24 as a service |
| Support | Community, best effort | Per agreement |

## The short version

**Using cra24 to produce your own compliance dossiers is free, forever, under any
licence, for any company of any size.** Running the CLI on your build, filing your
own reports, publishing your own advisories — the AGPL asks nothing of you,
because you are not conveying the software to anyone.

The AGPL only bites in two situations:

1. **You ship cra24, or code derived from it, inside a product you distribute.**
   Then your product's source must be available to its recipients under the AGPL.
2. **You let other people use cra24 over a network** — a SaaS, a hosted portal, a
   customer-facing compliance dashboard. AGPL section 13 means your users are
   entitled to the complete corresponding source of what you are running, modifications
   included.

If either of those describes your plan and you do not want to open your source, buy
a commercial licence. That is the entire business model, stated plainly.

## Why AGPL and not Apache

Apache-2.0 would let a larger vendor wrap cra24 in a hosted product, sell it, and
contribute nothing back. That has happened to enough infrastructure projects that the
pattern needs no defending. The AGPL does not prevent competition; it requires that a
competitor who builds on this work plays by the same rules.

Embedded engineers get the full tool with no strings, because running it on your own
build is not distribution. The people asked to pay are the ones turning it into a
product.

## What is *not* AGPL

Some parts are deliberately permissive so that adoption is frictionless:

| Component | Licence | Why |
| --- | --- | --- |
| Emitted documents (your CSAF, OpenVEX, SRP dossiers, evidence ledger) | **Yours.** No licence claimed. | Output of a tool is not a derivative work of the tool. |
| `docs/` and the SRP field spec in `src/cra24/data/*.json` | CC-BY-4.0 | The regulation mapping should be freely reusable, including by competitors. Facts about a law should not be enclosed. |
| CI integrations (GitHub Action, GitLab template) — planned | Apache-2.0 | They are clients. Making them permissive removes every excuse not to adopt them. |
| Vendored third-party schemas under `src/cra24/data/schemas/` | Their own terms | See `NOTICE`. |

## Buying a commercial licence

Email `amr.benabdessalem@gmail.com` with what you are building, which version
range you need, and roughly how many device families it covers.

Licences are granted per organisation, are perpetual for the version range
purchased, and include the right to keep your modifications private. Terms are
sent on request rather than published: a contract template nobody has negotiated
against is not terms, and the specifics depend on what you are shipping.

## Contributing

Contributions require a signed Contributor Licence Agreement — see
[`CLA.md`](CLA.md). The CLA is what makes dual licensing possible: without the
right to relicense contributed code, a single AGPL contribution would make the
commercial licence unofferable. The CLA does not take your copyright; you keep it
and grant a parallel licence.

---

*This file explains the intent of the licensing. The operative documents are
`LICENSE` and `CLA.md`, plus the commercial terms sent on request. None of this
is legal advice.*
