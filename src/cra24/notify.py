# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Notifiers for watch mode.

The alert is not the product. Every scanner on earth sends alerts, and a PSIRT
inbox full of them is how a real one gets missed. What makes this worth waking up
for is that the message points at a **dossier that is already written**, with the
clock already started at the moment of detection and the remaining mandatory
fields already listed.

So every notifier says the same four things, in this order:

1. what it is, and whether it is reportable under Article 14(1);
2. when the clock started and how long is left;
3. where the dossier is;
4. which fields still need a human.

Notifiers never raise. A webhook that is down must not stop the dossier being
written or the next product being checked — losing the alert is recoverable,
losing the run is not.
"""

from __future__ import annotations

import json
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Protocol

from . import GENERATOR, __version__
from .logging import get

log = get("notify")

TIMEOUT = 20.0


@dataclass
class Alert:
    """One thing that happened and needs a person."""

    product: str
    product_version: str
    cve: str
    status: str
    reportable: bool
    summary: str
    detected_at: str
    early_warning_due: str = ""
    remaining: str = ""
    dossier_path: str = ""
    gaps: list[str] = field(default_factory=list)
    severity: str = ""
    epss: float | None = None
    ransomware: bool = False
    components: list[str] = field(default_factory=list)

    @property
    def urgency(self) -> str:
        return "ACTION REQUIRED" if self.reportable else "for review"

    def subject(self) -> str:
        prefix = "CRA 24h clock" if self.reportable else "CRA watch"
        return f"[{prefix}] {self.cve} in {self.product} {self.product_version}".strip()

    def to_dict(self) -> dict[str, Any]:
        return {
            "product": self.product,
            "product_version": self.product_version,
            "cve": self.cve,
            "status": self.status,
            "reportable": self.reportable,
            "summary": self.summary,
            "detected_at": self.detected_at,
            "early_warning_due": self.early_warning_due,
            "remaining": self.remaining,
            "dossier_path": self.dossier_path,
            "gaps": self.gaps,
            "severity": self.severity,
            "epss": self.epss,
            "ransomware": self.ransomware,
            "components": self.components,
            "generator": GENERATOR,
            "tool_version": __version__,
        }

    def to_text(self) -> str:
        lines = [
            f"{self.cve} — {self.urgency}",
            "",
            f"Product:   {self.product} {self.product_version}".rstrip(),
            f"Status:    {self.status}",
        ]
        if self.components:
            lines.append(f"In:        {', '.join(self.components)}")
        if self.severity:
            lines.append(f"Severity:  {self.severity}")
        if self.epss is not None:
            lines.append(f"EPSS:      {self.epss:.4f}")
        if self.ransomware:
            lines.append("Note:      known use in ransomware campaigns")

        lines += ["", self.summary, ""]

        if self.reportable:
            lines += [
                "ARTICLE 14(1) CLOCK",
                f"  became aware   {self.detected_at}",
                f"  early warning  due {self.early_warning_due}"
                + (f"  ({self.remaining} left)" if self.remaining else ""),
                "",
            ]
        else:
            lines += [
                "Not reportable on the evidence so far. No clock has been started.",
                "",
            ]

        if self.dossier_path:
            lines += [f"Dossier:   {self.dossier_path}", ""]

        if self.gaps:
            lines += [f"STILL NEEDED FROM A HUMAN ({len(self.gaps)}):"]
            lines += [f"  - {gap}" for gap in self.gaps]
            lines.append("")

        lines += [
            "-- ",
            f"{GENERATOR}",
            "Unofficial. Review every field before submitting.",
        ]
        return "\n".join(lines)


class Notifier(Protocol):
    def send(self, alert: Alert) -> bool: ...  # pragma: no cover


class StdoutNotifier:
    """The default. Prints the alert; a cron job's mail wrapper does the rest."""

    name = "stdout"

    def send(self, alert: Alert) -> bool:
        print(alert.to_text())
        print()
        return True


class FileNotifier:
    """Append alerts to a file, for a log shipper or just for a record."""

    name = "file"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def send(self, alert: Alert) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(alert.to_dict(), sort_keys=True) + "\n")
            return True
        except OSError as exc:
            log.error("could not write alert to %s: %s", self.path, exc)
            return False


class WebhookNotifier:
    """POST the alert as JSON.

    The payload carries both the structured fields and a rendered ``text``, so a
    Slack or Mattermost incoming webhook renders something readable without a
    transform in between.
    """

    name = "webhook"

    def __init__(self, url: str, *, headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.headers = headers or {}

    def send(self, alert: Alert) -> bool:
        payload = dict(alert.to_dict())
        payload["text"] = alert.to_text()
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"cra24/{__version__}",
                **self.headers,
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as resp:
                ok = 200 <= resp.status < 300
                if not ok:
                    log.error("webhook returned HTTP %s", resp.status)
                return ok
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.error("webhook %s failed: %s", self.url, exc)
            return False


class EmailNotifier:
    """Send the alert by SMTP.

    Credentials come from the environment, never from a config file that might
    end up in a repository: ``CRA24_SMTP_HOST``, ``CRA24_SMTP_PORT``,
    ``CRA24_SMTP_USER``, ``CRA24_SMTP_PASSWORD``, ``CRA24_SMTP_STARTTLS``.
    """

    name = "email"

    def __init__(
        self,
        to: str | list[str],
        sender: str = "",
        *,
        host: str = "",
        port: int = 0,
        user: str = "",
        password: str = "",
        starttls: bool = True,
    ) -> None:
        import os

        self.to = [to] if isinstance(to, str) else list(to)
        self.host = host or os.environ.get("CRA24_SMTP_HOST", "localhost")
        self.port = port or int(os.environ.get("CRA24_SMTP_PORT", "25") or 25)
        self.user = user or os.environ.get("CRA24_SMTP_USER", "")
        self.password = password or os.environ.get("CRA24_SMTP_PASSWORD", "")
        self.starttls = starttls and os.environ.get("CRA24_SMTP_STARTTLS", "1") not in (
            "0",
            "false",
            "",
        )
        self.sender = sender or os.environ.get("CRA24_SMTP_FROM", f"cra24@{self.host}")

    def send(self, alert: Alert) -> bool:
        message = EmailMessage()
        message["Subject"] = alert.subject()
        message["From"] = self.sender
        message["To"] = ", ".join(self.to)
        if alert.reportable:
            # So a mail client can filter on it, and so the rule survives a
            # subject-line change later.
            message["X-CRA24-Reportable"] = "yes"
            message["Importance"] = "high"
        message["X-CRA24-CVE"] = alert.cve
        message.set_content(alert.to_text())

        try:
            with smtplib.SMTP(self.host, self.port, timeout=TIMEOUT) as smtp:
                if self.starttls:
                    smtp.starttls(context=ssl.create_default_context())
                if self.user:
                    smtp.login(self.user, self.password)
                smtp.send_message(message)
            return True
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            log.error("could not send alert mail to %s: %s", ", ".join(self.to), exc)
            return False


def build(spec: str) -> Notifier:
    """Build a notifier from a ``scheme:target`` string.

    ``stdout``, ``file:/var/log/cra24.jsonl``, ``webhook:https://…``,
    ``email:psirt@example.com``.
    """
    spec = (spec or "").strip()
    if not spec or spec == "stdout":
        return StdoutNotifier()
    scheme, _, target = spec.partition(":")
    scheme = scheme.lower()
    if scheme == "file":
        return FileNotifier(target)
    if scheme == "webhook":
        return WebhookNotifier(target)
    if scheme == "email":
        return EmailNotifier([t.strip() for t in target.split(",") if t.strip()])
    if scheme in ("http", "https"):
        return WebhookNotifier(spec)

    from .errors import ConfigError

    raise ConfigError(
        f"unrecognised notifier {spec!r}",
        hint="use stdout, file:PATH, webhook:URL or email:ADDRESS",
    )


def send_all(notifiers: list[Notifier], alert: Alert) -> int:
    """Deliver to every notifier. Returns how many succeeded."""
    delivered = 0
    for notifier in notifiers:
        try:
            if notifier.send(alert):
                delivered += 1
        except Exception as exc:
            log.error("notifier %s raised: %s", getattr(notifier, "name", notifier), exc)
    return delivered
