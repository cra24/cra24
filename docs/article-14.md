# Article 14, mapped to the code

Regulation (EU) 2024/2847, Article 14 — *Reporting obligations of manufacturers*.

> **Unofficial.** This is a working engineer's reading, not legal advice, and not
> an authentic text. Only the version on EUR-Lex is authentic. Where this
> document and the regulation differ, the regulation wins and this document is a
> bug.

---

## The two tracks

Article 14 contains two separate reporting duties that share a shape and differ
in their triggers, their content and their final deadline.

| | Actively exploited vulnerability | Severe incident |
| --- | --- | --- |
| Paragraphs | 14(1), 14(2) | 14(3), 14(4) |
| Trigger | A vulnerability **in your product** that is **actively exploited** | An incident **having an impact on the security** of your product |
| Early warning | 24 h | 24 h |
| Notification | 72 h | 72 h |
| Final report | 14 days after a corrective or mitigating measure is available | 1 month after the 72-hour notification |
| In cra24 | `--track vulnerability` (default) | `--track incident` |

**The word that does the work in 14(1) is "actively exploited".** Not "critical",
not "unpatched", not "high CVSS". A serious unpatched vulnerability with no
evidence of exploitation is something you fix under Annex I Part II; it is not an
Article 14 event. cra24 refuses to mark anything reportable without
`--actively-exploited yes`, and says why.

---

## Clause by clause

### 14(1) — the vulnerability track

> A manufacturer shall notify any actively exploited vulnerability contained in
> the product with digital elements that it becomes aware of […] simultaneously
> to the CSIRT designated as coordinator […] and to ENISA.

Two conditions, both required: **contained in the product**, and **actively
exploited**.

`triage.py` answers the first and refuses to answer the second, because the tool
cannot know it. `Triage.reportable` is true only when the product is `affected`
*and* the caller asserted active exploitation.

**Simultaneously** matters: the SRP submits once and routes to both. You do not
file twice, and contacting your CSIRT directly does not discharge the obligation.

#### 14(1)(a) — early warning, 24 hours

> an early warning […] without undue delay and in any event within 24 hours of
> the manufacturer becoming aware of the actively exploited vulnerability,
> indicating […] the Member States […] on the territory of which the product […]
> has been made available

- **`clock.timeline()[early_warning]`** — 24 hours from `--aware-at`.
- **"becoming aware"** is the instant the clock starts, and reconstructing it
  later is not possible. Record it the moment it happens. `became_aware_at` is a
  required field of the dossier.
- **"without undue delay and in any event within 24 hours"** means 24 hours is
  the outer bound, not a budget to spend.
- **The Member States are named in the clause itself**, which is why cra24 treats
  `member_states` as a blocking gap rather than an optional field, even though
  public guidance describes the platform field as "required if available".

#### 14(1)(b) — notification, 72 hours

> a vulnerability notification […] within 72 hours […] which […] shall provide
> general information […] about the product […] the general nature of the
> exploit and of the vulnerability concerned as well as any corrective or
> mitigating measures taken, and corrective or mitigating measures that users can
> take

- **`--stage notification`** adds `vulnerability_nature`, `initial_assessment`,
  `corrective_measures` and `user_measures` as required fields, on top of
  everything the early warning carried.
- **72 hours runs from awareness**, not from when you filed the early warning.
  The platform's own counter has been reported to show the latter. Trust
  `cra24 clock`.

### 14(2) — the vulnerability final report

> a final report […] no later than 14 days after a corrective or mitigating
> measure is available

- **`--measure-available 2026-09-25T00:00:00Z`** starts this clock. Until you set
  it, `cra24` shows the stage as `not-started` and says so explicitly, because
  the alternative — showing no deadline — reads like there is nothing to do.
- **The platform shows no counter for this at all**, since it cannot know when
  your fix ships. If you track it nowhere else, track it here.
- Content: a description of the vulnerability including its severity and impact,
  information about the malicious actor where available, and details of the
  security update or other corrective measure.

### 14(3) — the incident track

> a manufacturer shall notify any severe incident having an impact on the
> security of the product with digital elements

An incident is severe when it **negatively affects or is capable of negatively
affecting** the product's ability to protect the availability, authenticity,
integrity or confidentiality of data or functions, or when it has led or can lead
to the introduction or execution of malicious code.

"Capable of" is doing a lot of work there: an incident need not have caused harm
yet.

#### 14(3)(a) and (b)

Same 24 and 72 hour shape. Two differences from the vulnerability track:

- The early warning must indicate whether the incident is **suspected of being
  caused by unlawful or malicious acts**. cra24 makes `malicious_intent` a
  blocking field on this track and merely recommended on the other.
- The 72-hour notification adds an assessment of the incident, including its
  severity and impact, and — where available — indicators of compromise.

### 14(4) — the incident final report

> a final report […] within one month after the submission of the incident
> notification

Note the anchor: **one month after the 72-hour notification**, not after
awareness and not after the incident is resolved. cra24 computes it as
awareness + 72 h + 30 days.

### 14(5) and (6) — routing and exceptional circumstances

The CSIRT designated as coordinator is determined by your **Member State of main
establishment**, and is fixed once when your assigned representative registers.
Selecting the wrong one invalidates a notification and forces a resubmission,
which is why cra24 treats `coordinator_csirt` as a derived field that blocks
submission when empty.

A receiving CSIRT may, on cybersecurity grounds, delay onward dissemination —
"particularly exceptional circumstances", recorded on the platform as *72h
Submitted under PEC*. The usual reason is avoiding a broadcast that would expose
unpatched devices. The `sensitivity` field of the 72-hour stage is where you make
that case.

### 14(8) — telling your users

> the manufacturer shall […] inform the impacted users […] and, where
> appropriate, all users, of that vulnerability or incident and, where necessary,
> of any risk mitigation and corrective measures […] in a machine-readable
> format

**This is the clause the CSAF advisory and the OpenVEX document answer.** They
are not a nice-to-have: "machine-readable format" is in the text.

It is also the clause most likely to be asked about by an integrator who buys
your module and has their own CRA duties. An embedded supplier who can hand over
a valid CSAF advisory on request is doing something most of their competitors
cannot.

### 14(9) — the CSIRT may act if you do not

Where a manufacturer fails to notify in time, the coordinator CSIRT may inform
users itself. Worth knowing as a motivation: the alternative to filing is not
nothing happening.

---

## The clocks, as code

```python
from cra24.clock import timeline, Track

tl = timeline("2026-09-17T08:30:00Z", track=Track.VULNERABILITY,
              measure_available_at="2026-09-25T00:00:00Z")

tl["early_warning"].due_at      # 2026-09-18T08:30:00+00:00
tl["notification"].due_at       # 2026-09-20T08:30:00+00:00
tl["final_report"].due_at       # 2026-10-09T00:00:00+00:00
tl["early_warning"].urgency()   # Urgency.PENDING | DUE_SOON | OVERDUE | SUBMITTED
tl.worst_urgency()              # for a single headline state
```

`Urgency.DUE_SOON` begins at the last quarter of each window: six hours into a
24-hour clock, eighteen into a 72-hour one.

Already filed a stage? Pass it, and that stage stops showing as overdue:

```python
timeline(aware_at, submitted={"early_warning": "2026-09-18T07:00:00Z"})
```

---

## What cra24 deliberately does not do

- **It does not decide that a vulnerability is actively exploited.** You tell it,
  and it records when you did.
- **It does not submit anything.** The platform has no API. Even if it gains one,
  a filing under this regulation is a statement by a legal person, and that
  person should press the button.
- **It does not assess severity.** `--severity` is your call.
- **It does not tell you whether an incident is severe.** The test in 14(3) is a
  judgement about your product's security properties, and no tool can make it
  from a build tree.
- **It does not make you compliant.** It organises the evidence you already have
  and drafts the documents, so that the parts a human must do are the only parts
  left.

---

## Dates worth having in one place

| Date | What happens |
| --- | --- |
| 11 September 2026 | Article 14 reporting obligations begin binding manufacturers. The SRP goes live. |
| 11 December 2027 | Full application, including Annex I requirements, technical documentation, conformity assessment and CE marking. Open-source software steward obligations begin. |

The gap between those two dates is the current situation: you must report
actively exploited vulnerabilities **now**, while the SBOM and conformity
machinery is still being built. That gap is what cra24 is for.

---

## Sources

- [Regulation (EU) 2024/2847 — the authentic text, EUR-Lex](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [Cyber Resilience Act reporting obligations — European Commission](https://digital-strategy.ec.europa.eu/en/policies/cra-reporting)
- [Single Reporting Platform — ENISA](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp)
- [Article 14, annotated — european-cyber-resilience-act.com](https://www.european-cyber-resilience-act.com/Cyber_Resilience_Act_Article_14.html)
