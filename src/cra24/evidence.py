# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Hash-chained evidence ledger.

CRA technical documentation has to be kept for ten years, or for the support
period, whichever is longer. What matters at year eight is not the dossier alone
but proof of *which inputs produced it* and that nobody quietly edited it since.

Every emit appends one record carrying the SHA-256 of each artefact and the hash
of the previous record. Changing any artefact, or any earlier record, breaks the
chain at a detectable point.

What this is and is not:

* It **is** tamper-evident. You can prove to yourself, and show an auditor, that
  the chain is intact and that a given file is the one the tool wrote.
* It is **not** a trusted timestamp. The recorded times are your machine's. If
  you need to prove to a third party *when* something existed, anchor the head
  hash somewhere you do not control — an RFC 3161 timestamp authority, a
  transparency log, or the simplest thing that works: mail the head hash to
  yourself and keep the mail.
* Optional HMAC over each record raises the bar from "an editor" to "someone who
  also has the key". Keep the key off the build machine or it protects nothing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import EvidenceError

LEDGER = "ledger.jsonl"
GENESIS = "0" * 64
#: Environment variable holding the optional HMAC key, hex encoded.
KEY_ENV = "CRA24_EVIDENCE_KEY"


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    try:
        with Path(path).open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
    except OSError as exc:
        raise EvidenceError(f"cannot hash {path}: {exc}") from exc
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(record: dict[str, Any]) -> bytes:
    """Serialise a record deterministically. The chain depends on this being stable."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _record_hash(record: dict[str, Any]) -> str:
    """Hash a record excluding its own integrity fields."""
    body = {k: v for k, v in record.items() if k not in ("hmac",)}
    return sha256_bytes(_canonical(body))


def _key() -> bytes | None:
    raw = os.environ.get(KEY_ENV, "").strip()
    if not raw:
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode("utf-8")


def key_info() -> dict[str, Any]:
    """How the configured key was interpreted, for ``cra24 doctor``.

    A value that happens to parse as hex is decoded as hex, so the passphrase
    ``deadbeef`` becomes four bytes of key material rather than eight. That is
    not wrong — a hex key is the sensible way to carry 32 random bytes through
    an environment variable — but it is surprising if you meant a passphrase,
    and it is invisible at the point where it matters.

    Changing the rule would invalidate every ledger already signed under the
    old one, so the interpretation stands and is reported instead.
    """
    raw = os.environ.get(KEY_ENV, "").strip()
    if not raw:
        return {"set": False}
    key = _key() or b""
    try:
        bytes.fromhex(raw)
        decoded_as = "hex"
    except ValueError:
        decoded_as = "utf-8 text"
    return {
        "set": True,
        "decoded_as": decoded_as,
        "bytes": len(key),
        # 16 bytes is the floor below which an HMAC key stops being the reason
        # an attacker cannot forge a record.
        "weak": len(key) < 16,
    }


@dataclass
class Record:
    seq: int
    recorded_at: str
    event: str
    prev: str
    artefacts: dict[str, str]
    meta: dict[str, Any]
    hmac: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "seq": self.seq,
            "recorded_at": self.recorded_at,
            "event": self.event,
            "prev": self.prev,
            "artefacts": self.artefacts,
            "meta": self.meta,
        }
        if self.hmac:
            d["hmac"] = self.hmac
        return d

    @property
    def digest(self) -> str:
        return _record_hash(self.to_dict())


class Ledger:
    """An append-only, hash-chained record of what the tool produced."""

    def __init__(self, directory: str | Path) -> None:
        self.dir = Path(directory)
        self.path = self.dir / LEDGER

    # -- reading -----------------------------------------------------------

    def __iter__(self) -> Iterator[Record]:
        if not self.path.is_file():
            return
        for lineno, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EvidenceError(f"{self.path}:{lineno} is not valid JSON: {exc}") from exc
            yield Record(
                seq=data.get("seq", lineno - 1),
                recorded_at=data.get("recorded_at", ""),
                event=data.get("event", ""),
                prev=data.get("prev", GENESIS),
                artefacts=data.get("artefacts", {}),
                meta=data.get("meta", {}),
                hmac=data.get("hmac"),
            )

    def records(self) -> list[Record]:
        return list(self)

    def _last_line(self) -> str:
        """The final non-empty line, read from the end of the file.

        An append needs two facts about the ledger: how many records it has and
        the digest of the last one. Both live on the final line, so reading the
        whole file to find them made every append cost the length of the whole
        history — on a watch that appends hourly for a year, an accumulating
        tax for no reason.
        """
        if not self.path.is_file():
            return ""
        size = self.path.stat().st_size
        if size == 0:
            return ""
        with self.path.open("rb") as fh:
            window = 4096
            while True:
                start = max(0, size - window)
                fh.seek(start)
                chunk = fh.read(size - start)
                lines = [ln for ln in chunk.split(b"\n") if ln.strip()]
                # Keep growing the window until the last line is whole, which is
                # only in doubt while the window still starts mid-file.
                if lines and (start == 0 or len(lines) > 1):
                    return lines[-1].decode("utf-8")
                if start == 0:
                    return ""
                window *= 2

    def _last_record(self) -> Record | None:
        line = self._last_line()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvidenceError(
                f"the last line of {self.path} is not valid JSON: {exc}"
            ) from exc
        return Record(
            seq=data.get("seq", 0),
            recorded_at=data.get("recorded_at", ""),
            event=data.get("event", ""),
            prev=data.get("prev", GENESIS),
            artefacts=data.get("artefacts", {}),
            meta=data.get("meta", {}),
            hmac=data.get("hmac"),
        )

    def head(self) -> str:
        """Hash of the last record, or the genesis value for an empty ledger."""
        last = self._last_record()
        return last.digest if last is not None else GENESIS

    # -- writing -----------------------------------------------------------

    def append(
        self,
        event: str,
        artefacts: Sequence[str | Path] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> Record:
        self.dir.mkdir(parents=True, exist_ok=True)
        last = self._last_record()
        digests = {}
        for a in artefacts or []:
            p = Path(a)
            try:
                key = str(p.relative_to(self.dir.parent))
            except ValueError:
                key = str(p)
            digests[key] = sha256_file(p)

        rec = Record(
            seq=last.seq + 1 if last is not None else 0,
            recorded_at=datetime.now(timezone.utc).isoformat(),
            event=event,
            prev=last.digest if last is not None else GENESIS,
            artefacts=dict(sorted(digests.items())),
            meta=dict(sorted((meta or {}).items())),
        )
        secret = _key()
        if secret:
            rec.hmac = hmac.new(secret, _canonical(rec.to_dict()), hashlib.sha256).hexdigest()

        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec.to_dict(), sort_keys=True, ensure_ascii=False) + "\n")
        return rec

    # -- verification ------------------------------------------------------

    def verify(self, check_files: bool = True, expect_head: str = "") -> tuple[bool, list[str]]:
        """Verify the chain, the HMACs if a key is set, and optionally the files.

        Returns ``(ok, messages)``. Messages are ordered and human-readable; the
        first failure is the one that matters, the rest are consequences.

        ``expect_head`` closes the one hole the chain cannot close by itself.
        Deleting whole records from the end leaves a shorter chain that is still
        internally consistent, so truncation verifies clean — which is why the
        module tells you to anchor the head hash somewhere you do not control.
        Pass the value you anchored and that anchor becomes checkable: the chain
        must not only be intact, it must end where you said it ended.
        """
        if not self.path.is_file():
            return False, [f"no ledger at {self.path}"]

        problems: list[str] = []
        key = _key()
        prev = GENESIS
        count = 0

        for rec in self:
            count += 1
            if rec.prev != prev:
                problems.append(
                    f"record {rec.seq}: chain broken — links to {rec.prev[:12]}…, "
                    f"expected {prev[:12]}…"
                )
            if key:
                if not rec.hmac:
                    problems.append(f"record {rec.seq}: no HMAC, but a key is configured")
                else:
                    body = {k: v for k, v in rec.to_dict().items() if k != "hmac"}
                    expected = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(expected, rec.hmac):
                        problems.append(f"record {rec.seq}: HMAC does not match")
            elif rec.hmac:
                problems.append(
                    f"record {rec.seq}: carries an HMAC but no key is configured; "
                    f"set {KEY_ENV} to verify it"
                )
            if check_files:
                for rel, digest in rec.artefacts.items():
                    target = self.dir.parent / rel
                    if not target.is_file():
                        problems.append(f"record {rec.seq}: artefact missing: {rel}")
                        continue
                    actual = sha256_file(target)
                    if actual != digest:
                        problems.append(
                            f"record {rec.seq}: {rel} has changed since it was recorded"
                        )
            prev = rec.digest

        if count == 0:
            return False, ["ledger is empty"]

        if expect_head:
            wanted = expect_head.strip().lower()
            if not prev.startswith(wanted):
                problems.append(
                    f"head is {prev[:16]}…, expected {wanted[:16]}… — the chain is "
                    "intact but does not end where it should; records have been "
                    "removed from the end, or this is not the ledger you anchored"
                )

        if problems:
            return False, problems
        return True, [
            f"chain intact over {count} record{'s' if count != 1 else ''}",
            f"head {prev[:16]}…",
            "HMAC verified" if key else f"no HMAC key set ({KEY_ENV} unset)",
            *(["head matches the anchor you supplied"] if expect_head else []),
        ]

    def summary(self) -> dict[str, Any]:
        recs = self.records()
        return {
            "ledger": str(self.path),
            "records": len(recs),
            "head": self.head(),
            "first_recorded_at": recs[0].recorded_at if recs else None,
            "last_recorded_at": recs[-1].recorded_at if recs else None,
            "events": sorted({r.event for r in recs}),
            "artefacts": sum(len(r.artefacts) for r in recs),
        }


# -- module-level convenience, kept stable for the CLI -----------------------


def append(
    evidence_dir: str | Path,
    event: str,
    artefacts: Sequence[str | Path] | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return Ledger(evidence_dir).append(event, artefacts, meta).to_dict()


def verify(evidence_dir: str | Path, check_files: bool = True) -> tuple[bool, list[str]]:
    return Ledger(evidence_dir).verify(check_files=check_files)
