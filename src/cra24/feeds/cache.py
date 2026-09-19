# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""On-disk cache for feed data.

The cache is not an optimisation here, it is the feature. A build machine on a
factory network often has no route to the internet, and an incident is the worst
possible moment to discover that. So cra24 is built to run from a cache that was
populated somewhere else and copied in, and to say clearly how old that cache is
rather than silently answering from stale data.

Layout::

    .cra24-cache/
      kev/catalog.json          the payload, exactly as fetched
      kev/catalog.json.meta     fetched_at, etag, last_modified, url, sha256

The meta file is separate so that the payload stays byte-identical to what the
server sent. That matters for the evidence ledger: you can hash the cached
artefact and show it is the file CISA published.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from ..errors import Cra24Error

DEFAULT_DIR = ".cra24-cache"
#: Environment variable that relocates the cache, for shared or read-only setups.
DIR_ENV = "CRA24_CACHE_DIR"


class CacheError(Cra24Error):
    exit_code = 7


@dataclass
class Entry:
    """What we know about one cached payload."""

    url: str = ""
    fetched_at: str = ""
    etag: str = ""
    last_modified: str = ""
    sha256: str = ""
    bytes: int = 0
    #: Set when the last attempt was served from cache after a 304.
    revalidated_at: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def age(self, now: datetime | None = None) -> timedelta | None:
        if not self.fetched_at:
            return None
        now = now or datetime.now(timezone.utc)
        try:
            stamp = datetime.fromisoformat(self.fetched_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        return now - stamp

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def cache_root(explicit: str | Path | None = None) -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get(DIR_ENV, "").strip()
    return Path(env) if env else Path(DEFAULT_DIR)


class Cache:
    """A directory of cached feed payloads, keyed by feed name and file name."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = cache_root(root)

    # -- paths -------------------------------------------------------------

    @staticmethod
    def _contained(part: str, label: str) -> str:
        """Refuse a path component that would leave the cache directory.

        Feed payloads are keyed by identifiers that arrive from outside: a CVE
        id typed on the command line, but also one read out of an SBOM or a
        cve-check summary that some other build produced. ``root / feed / name``
        with an absolute ``name`` silently becomes ``name``, and one ``..`` too
        many walks out of the cache entirely, so the containment is enforced
        here rather than trusted at each of the five call sites.
        """
        cleaned = (part or "").strip()
        if not cleaned:
            raise CacheError(f"empty {label} for a cache entry")
        if PurePosixPath(cleaned).is_absolute() or Path(cleaned).is_absolute():
            raise CacheError(f"{label} {cleaned!r} is an absolute path")
        # normpath resolves ".." textually, which is what we want: no filesystem
        # lookup, and symlinks cannot be used to defeat the check later.
        normalised = os.path.normpath(cleaned)
        if normalised == ".." or normalised.startswith((".." + os.sep, ".." + "/")):
            raise CacheError(f"{label} {cleaned!r} escapes the cache directory")
        return normalised

    def path(self, feed: str, name: str) -> Path:
        return self.root / self._contained(feed, "feed") / self._contained(name, "entry name")

    def _meta_path(self, feed: str, name: str) -> Path:
        return self.path(feed, name).with_name(self.path(feed, name).name + ".meta")

    # -- reading -----------------------------------------------------------

    def has(self, feed: str, name: str) -> bool:
        return self.path(feed, name).is_file()

    def read_bytes(self, feed: str, name: str) -> bytes:
        p = self.path(feed, name)
        if not p.is_file():
            raise CacheError(
                f"{feed}/{name} is not in the cache at {self.root}",
                hint="run `cra24 feeds sync` where there is a network, or copy a "
                "populated cache directory across and point CRA24_CACHE_DIR at it",
            )
        return p.read_bytes()

    def read_json(self, feed: str, name: str) -> Any:
        raw = self.read_bytes(feed, name)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CacheError(
                f"cached {feed}/{name} is not valid JSON: {exc}",
                hint="the cached copy is damaged; delete it and re-sync",
            ) from exc

    def meta(self, feed: str, name: str) -> Entry:
        p = self._meta_path(feed, name)
        if not p.is_file():
            return Entry()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return Entry()
        known = set(Entry.__dataclass_fields__)
        return Entry(**{k: v for k, v in data.items() if k in known})

    def age(self, feed: str, name: str, now: datetime | None = None) -> timedelta | None:
        return self.meta(feed, name).age(now)

    def is_fresh(
        self, feed: str, name: str, max_age: timedelta, now: datetime | None = None
    ) -> bool:
        if not self.has(feed, name):
            return False
        age = self.age(feed, name, now)
        return age is not None and age <= max_age

    # -- writing -----------------------------------------------------------

    def write(
        self,
        feed: str,
        name: str,
        payload: bytes,
        *,
        url: str = "",
        etag: str = "",
        last_modified: str = "",
        extra: dict[str, Any] | None = None,
    ) -> Entry:
        p = self.path(feed, name)
        p.parent.mkdir(parents=True, exist_ok=True)
        # Write through a temporary file: a half-written cache entry that looks
        # complete is worse than no cache entry, because nothing will notice.
        tmp = p.with_name(f".{p.name}.{os.getpid()}.{time.time_ns()}.tmp")
        tmp.write_bytes(payload)
        tmp.replace(p)

        entry = Entry(
            url=url,
            fetched_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            etag=etag,
            last_modified=last_modified,
            sha256=hashlib.sha256(payload).hexdigest(),
            bytes=len(payload),
            extra=extra or {},
        )
        self._meta_path(feed, name).write_text(
            json.dumps(entry.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return entry

    def touch_revalidated(self, feed: str, name: str) -> Entry:
        """Record that the server confirmed the cached copy is still current."""
        entry = self.meta(feed, name)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        entry.revalidated_at = now
        # A 304 means the payload is current as of now, so the freshness clock
        # restarts. Keeping the original fetched_at would make a file the server
        # just confirmed look stale.
        entry.fetched_at = now
        self._meta_path(feed, name).write_text(
            json.dumps(entry.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return entry

    # -- introspection -----------------------------------------------------

    def inventory(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not self.root.is_dir():
            return out
        for meta_file in sorted(self.root.rglob("*.meta")):
            payload = meta_file.with_name(meta_file.name[: -len(".meta")])
            rel = payload.relative_to(self.root)
            feed = rel.parts[0] if len(rel.parts) > 1 else ""
            entry = self.meta(feed, payload.name)
            age = entry.age()
            out.append(
                {
                    "feed": feed,
                    "name": payload.name,
                    "present": payload.is_file(),
                    "fetched_at": entry.fetched_at,
                    "age_hours": round(age.total_seconds() / 3600, 1) if age else None,
                    "bytes": entry.bytes,
                    "sha256": entry.sha256,
                    "url": entry.url,
                }
            )
        return out
