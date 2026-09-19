# The SRP field spec

## Why it is a file and not code

ENISA's Single Reporting Platform publishes **no machine-readable field spec and
no API**. The field set is whatever the web form shows today, in English, and it
will change — the platform is weeks old and ENISA has said translation and
possible API access come in later phases.

So `src/cra24/data/srp-fields.json` is a reconstruction. Making it a data file
rather than Python has three consequences, all of them the point:

1. **A user can patch it** the day the form changes, without waiting for a
   release and without forking.
2. **It can carry its own provenance** — sources, a consultation date, a version
   — which code cannot do legibly.
3. **It can record where the public guidance disagrees with itself**, instead of
   silently picking one reading and presenting it as fact.

No field name appears anywhere in the emitter code. `emit/srp.py` reads the spec
and fills what it can.

---

## What is in it

```json
{
  "spec_version": "2026-09-17",
  "unofficial": true,
  "disclaimer": "Reconstructed from public documentation...",
  "sources": [{"title": "...", "url": "...", "consulted": "2026-09-17"}],
  "known_disagreements": [{"field": "severity", "note": "..."}],
  "stages": [{"id": "early_warning", "deadline_hours": 24, "fields": [...]}],
  "value_sets": {"eu_member_states": ["AT", "BE", ...]},
  "platform_notes": ["No API at launch...", ...]
}
```

### Field entries

```json
{
  "key": "became_aware_at",
  "label": "Date and time became aware",
  "requirement": "required",
  "type": "datetime",
  "help": "Starts all three clocks. Record it the moment it happens; you cannot reconstruct it later."
}
```

| `requirement` | Meaning in cra24 |
| --- | --- |
| `required` | Blocks submission when empty |
| `conditional` | Blocks only when `required_when` holds; otherwise listed as recommended |
| `derived` | cra24 fills it from the config or the build; blocks if it cannot |
| `optional` | Never blocks |

`conditional_track` limits a field to one track — `incident_nature` appears only
on the incident track, `security_update` only on the vulnerability track.

`inherits` on a stage pulls in every field of the earlier one, so the 72-hour
notification carries the early warning's answers plus its own.

### The condition grammar

```json
{"requirement": "conditional", "required_when": "notification_type == 'Severe incident'"}
```

That is the entire grammar: one field, `==`, one quoted literal. It is evaluated
by a five-line parser in `emit/srp.py`, **never** by `eval`.

This is deliberate and worth stating plainly: the spec is a file users are
encouraged to edit, and cra24 is often run on a build machine. Data that a user
edits never gets executed. There is a test asserting that
`__import__('os').system(...)` in a condition evaluates to `False` rather than
running.

---

## Recorded disagreements

The two places public guidance contradicts itself, as of the current spec
version:

### Severity at the 24-hour stage

One guide lists a severity level as mandatory in the early warning. Another lists
only a *notification level indicator* at 24 hours, with severity detail deferred
to the final report.

**What cra24 does:** asks for both, marks `severity` as conditional so it is
listed as recommended rather than blocking. You are never caught short, and you
are never blocked on a field that may not exist.

### Affected Member States

Article 14(1)(a) says the early warning *shall indicate* the Member States where
the product has been made available. Public guides describe the platform field as
"required if the information is available".

**What cra24 does:** treats it as blocking. The regulation names it in the
clause, and "we did not have the information" is an awkward position for a
manufacturer to take about its own distribution.

If you have seen the form and can settle either question, that is a valuable
issue to open.

---

## Reporting drift

**This is the single most valuable contribution to the project.**

If you have used the SRP and the form does not match `cra24 spec`, open a *field
spec drift* issue with:

- which stage (early warning, 72-hour notification, final report),
- which track (vulnerability or incident),
- the field's label as shown on screen,
- whether it was mandatory,
- the date you saw it.

You do not need to write code. A screenshot with the sensitive parts removed is
ideal, but a description is enough.

`srp-fields.json` should be the most accurate public description of that form
that exists. It gets there only if people who have seen it say so. That is also
why `docs/` and the data files are offered under CC-BY-4.0 in addition to the
AGPL: a public map of a public regulation should not be enclosed by anyone,
including this project.

---

## Patching it yourself

You do not need to wait for a release.

```bash
python -c "import cra24.config as c; print(c.DATA_DIR)"
# .../site-packages/cra24/data
```

Edit `srp-fields.json`, bump `spec_version` to something you will recognise
(`2026-10-02-local`, say), and re-run. The version appears in every dossier and
in every evidence record, so a document built against your patched spec says so.

Then please send the change upstream.

---

## Platform notes

Carried in the spec and printed by `cra24 spec`, because each one has cost
somebody a deadline:

- **No API at launch.** Submission is a human filling in a web form. Automating
  your own workflow up to that point is fine; automating the submission is not
  possible. ENISA has said API access may come in a later phase.
- **English only at launch.**
- **Registration is per natural person**, via EU Login with MFA — not per
  company. One primary assigned representative per manufacturer, up to twenty
  secondary representatives.
- **Registration cannot be done retroactively.** Your named representatives need
  working EU Login accounts *before* an incident. This is the single cheapest
  thing to get right and the most expensive to discover at 2am.
- **The coordinator CSIRT is chosen once**, determined by your Member State of
  main establishment. Selecting the wrong one invalidates the notification and
  forces a resubmission.
- **A reported platform defect** shows the 72-hour due date as 48 hours after
  early warning submission, rather than 72 hours from awareness. Trust your own
  clock. `cra24 clock` measures from awareness, which is the legal test.
- **There is no final-report counter** for actively exploited vulnerabilities,
  because the deadline depends on when your corrective measure ships.
- **If the platform is unavailable**, the obligation is discharged when you
  submit after it is restored. Contacting the CSIRT directly does not discharge
  it.

---

## Sources

Recorded in the spec file itself with consultation dates:

- [Single Reporting Platform — ENISA](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp)
- [CRA reporting obligations — European Commission](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting)
- [What ENISA actually requires — Sbomify](https://sbomify.com/2026/09/10/cra-single-reporting-platform-enisa-srp/)
- [ENISA SRP guide — CVD Portal](https://cvdportal.com/enisa-srp)

ENISA's own **AR User Manual** and **SRP Glossary** are the authoritative
documents. Check the spec against them for your own account before relying on it.
