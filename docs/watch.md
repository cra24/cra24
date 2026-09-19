# Watch mode

## What it is for

Not the alert. Every scanner on earth sends alerts, and a PSIRT inbox full of
them is exactly how a real one gets missed.

The thing waiting for you at 07:00 is a **dossier with four fields left to fill
and a clock that started at 03:14** — the difference between discovering an
obligation and being halfway through discharging it.

```
CVE-2023-5678 — ACTION REQUIRED

Product:   AcmeGateway 2.4.0
Status:    affected
In:        openssl
EPSS:      0.0044
Note:      known use in ransomware campaigns

CVE-2023-5678 is unpatched in openssl 3.0.12, shipped in AcmeGateway 2.4.0.

ARTICLE 14(1) CLOCK
  became aware   2026-09-18T03:14:00+00:00
  early warning  due 2026-09-19T03:14:00+00:00  (20h 1m left)

Dossier:   watch-dossiers/acmegateway/cve-2023-5678/cve-2023-5678-early-warning.md

STILL NEEDED FROM A HUMAN (2):
  - severity — Severity level
  - summary — Summary
```

---

## Three properties that make it usable

### An alert fires once

State is kept per product and CVE. A new alert is sent only when the verdict
changes in a direction that matters — not affected to affected, or not reportable
to reportable.

A watcher that re-sends the same finding every fifteen minutes trains its readers
to filter it, and then the one that mattered is filtered too.

```bash
$ cra24 watch --products products/ --once
1 product(s), 4 CVE(s) checked, 4 new alert(s), 0 unchanged

$ cra24 watch --products products/ --once
1 product(s), 4 CVE(s) checked, 0 new alert(s), 4 unchanged
```

### The clock starts at detection and never moves

`became_aware_at` is written the first time a product is seen to be affected, and
is **never rewritten**.

Article 14 runs from awareness. A tool that quietly refreshed that timestamp on
each poll would produce a dossier understating how long you have known, which is
the one error here with legal consequences. There is a test for it.

### One failure does not stop the pass

A malformed product file, an unreachable feed, a webhook that is down: logged,
recorded in `errors`, move on. Losing an alert is recoverable; losing the run is
not.

---

## Setting it up

### One product file per device family

```bash
cra24 scan --build-dir ~/yocto/gateway-build --config gateway.json \
           --out products/gateway.json
cra24 scan --build-dir ~/yocto/sensor-build --config sensor.json \
           --out products/sensor.json
```

A device family is a product line sharing a build configuration and a support
period. That is also the scope metric the commercial licence uses, and it is the
unit a CSIRT will ask about.

### Run it

```bash
# one pass, for cron or CI
cra24 watch --products products/ --once

# a loop
cra24 watch --products products/ --interval 3600

# with notifications
cra24 watch --products products/ --once \
  --notify email:psirt@example.com \
  --notify file:/var/log/cra24-alerts.jsonl
```

**Exit code 1 means a reportable finding**, so a cron job can alert on it without
parsing text. Exit 0 means nothing new needs you.

### Under systemd

`contrib/systemd/` has a hardened unit and a timer:

```bash
sudo cp contrib/systemd/cra24-watch.* /etc/systemd/system/
sudo useradd --system --home /var/lib/cra24 --shell /usr/sbin/nologin cra24
sudo install -d -o cra24 -g cra24 /var/lib/cra24/{products,dossiers,cache}
sudo cp products/*.json /var/lib/cra24/products/
sudo systemctl enable --now cra24-watch.timer
```

It is a **oneshot on a timer, not a long-lived daemon**: one less thing holding
memory for an hour between polls, and a crash is a failed unit you can see rather
than a process that quietly stopped watching. `SuccessExitStatus=0 1` is there
because a reportable finding is news, not a malfunction.

The timer carries `RandomizedDelaySec=20min`. Every installation polling CISA on
the hour is rude, and the feeds do not change often enough for the precision to
buy anything.

---

## Notifiers

| Spec | What it does |
| --- | --- |
| `stdout` | Prints the alert. The default; a cron wrapper mails it. |
| `file:/var/log/cra24.jsonl` | Appends JSON lines, for a log shipper |
| `webhook:https://…` | POSTs the alert as JSON, with a rendered `text` field so Slack or Mattermost renders it without a transform |
| `email:psirt@example.com` | SMTP |

Repeatable. SMTP credentials come from the environment, never from a config file
that might end up in a repository:

```bash
CRA24_SMTP_HOST=smtp.example.com
CRA24_SMTP_PORT=587
CRA24_SMTP_USER=cra24
CRA24_SMTP_PASSWORD=...
CRA24_SMTP_FROM=cra24@example.com
```

A reportable alert carries `X-CRA24-Reportable: yes`, so a mail rule can survive a
subject-line change later.

---

## What gets checked

By default, only CVEs the build reports as **unpatched or unknown**.

A CVE your layer patched does not become reportable because CISA added it to KEV
— you are not affected by it. Checking everything turns a two-second pass into a
thousand-request crawl for no gain. `--all-cves` overrides this when you are
auditing rather than watching.

---

## What it writes

```
watch-dossiers/
  acmegateway/
    cve-2023-5678/
      cve-2023-5678-early-warning.json
      cve-2023-5678-early-warning.md      ← the one you read
      cve-2023-5678.csaf.json
      cve-2023-5678.openvex.json
    evidence/
      ledger.jsonl                        ← hash-chained, one record per detection
products/
  watch-state.json                        ← the clocks
```

The evidence chain records that the finding was detected by the watcher, at that
instant, with that tool version and field spec version:

```bash
cra24 verify watch-dossiers/acmegateway/evidence --summary
```

`watch-state.json` is plain JSON on purpose. It has to be readable by a human at
3am and editable when the tool has got something wrong.

---

## Air-gapped

```bash
# on a machine with a network
cra24 feeds sync --force && tar -czf cache.tar.gz .cra24-cache

# on the build machine
export CRA24_CACHE_DIR=/var/lib/cra24/cache
cra24 watch --products products/ --once --offline
```

`--offline` never opens a socket. `--no-sync` uses the network for nothing but
what is already cached. See [feeds.md](feeds.md).

---

## Operating it

**Do not commit `watch-dossiers/` or `products/`.** They contain an
unpatched-vulnerability inventory of a shipping product. Both are in the default
`.gitignore`.

**Re-scan after every release.** The watcher checks the inventory it was given;
it does not know your firmware moved on. Wire `cra24 scan` into your build and
have it overwrite the product file.

**Deleting `watch-state.json` costs you one repeat alert per open finding.** That
is better than losing the clocks, which is why the error message says so rather
than silently starting fresh.

**A reportable alert is the start of a human process, not the end of one.** cra24
has drafted the dossier and started the clock. Deciding that the vulnerability is
genuinely actively exploited *in your product*, filling the severity and summary,
and pressing submit on the platform are yours.
