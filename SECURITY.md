# Security policy

## Reporting a vulnerability in cra24

**Do not open a public issue.**

Email `amr.benabdessalem@gmail.com` with:

- what the issue is,
- how to reproduce it,
- what an attacker gets,
- any version constraints you know about.

You will get an acknowledgement within **72 hours** and an assessment within
**14 days**. If you do not hear back in 72 hours, please chase — a missed mail is
more likely than silence.


### What happens next

1. **72 hours** — acknowledgement, and a first view on severity.
2. **14 days** — assessment, and a fix plan with dates.
3. **90 days** — coordinated disclosure, or sooner if a fix ships earlier, or
   immediately if the issue is already being exploited.

You will be credited in the advisory unless you ask not to be.

### A note on the irony

A tool for handling vulnerability reports should be exemplary at receiving them.
If this policy is slow, unclear, or does not work when you try it, that is itself
a bug worth reporting.

---

## What is in scope

- The `cra24` package and its command line interface.
- The bundled regulation data under `src/cra24/data/`, where an error could cause
  a manufacturer to miss a legal obligation. **This counts as a security issue
  here, even though it is data rather than code** — a field spec that says
  "optional" where the platform says "mandatory" causes a rejected filing under a
  24-hour clock, and that is the failure mode this project exists to prevent.
- The triage engine, where a wrong verdict could cause a real vulnerability to be
  published as `not_affected`. A demonstrated case where cra24 concludes
  `not_affected` or `fixed` from evidence that does not support it is a security
  issue, not an accuracy issue.
- The evidence ledger, where a tampering path that verification does not detect is
  a security issue.

## What is out of scope

- Vulnerabilities in the components cra24 *reports on*. Those belong to their own
  projects.
- The accuracy of upstream CVE data, NVD records, or a build system's own
  `cve-check` output. cra24 reads what the build wrote; it does not adjudicate it.
- Missing hardening in the example configurations, unless it leads somewhere.
- Anything requiring an attacker to already control the build machine cra24 runs
  on.

---

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.x | yes |
| 0.1.x | no — upgrade; 0.1 drops kernel CVEs from dossiers (see CHANGELOG) |

Until 1.0, security fixes land on the latest minor release only.

---

## How cra24 handles its own supply chain

- **No runtime dependencies.** The core package imports only the standard
  library. Validation needs `jsonschema`, and that is an optional extra.
- **Schemas are vendored, not fetched.** The CSAF, OpenVEX and CVSS schemas live
  in the repository with their provenance recorded in `NOTICE`. A compliance tool
  that needs the internet to check its own output is not one you can run during
  an incident on a factory network.
- **cra24 makes no network calls.** Not for telemetry, not for updates, not for
  CVE lookups. When feed clients arrive in a later release they will be opt-in,
  clearly named, and will say which host they contact.
- **Releases are built in CI from a tag** and the workflow is in the repository.

---

## For users: what cra24 does with your data

Worth stating plainly, because the files involved describe your product's attack
surface.

- Everything stays on the machine you run it on. Nothing is uploaded anywhere.
- `product.json`, `dossier/` and `evidence/` are in the default `.gitignore`.
  They contain an unpatched-vulnerability inventory of a shipping product; treat
  them as you would treat that.
- `CRA24_EVIDENCE_KEY`, if you set it, should not live on the build machine. A
  signing key stored next to what it signs protects nothing.
- The evidence ledger is **tamper-evident, not a trusted timestamp**. It proves
  the chain is intact; it does not prove to a third party *when* something
  existed. See [docs/evidence.md](docs/evidence.md) for how to anchor it if you
  need that.
