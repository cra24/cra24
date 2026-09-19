# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""HTTP plumbing shared by every feed client.

Three commitments this module exists to keep:

**cra24 makes no network call you did not ask for.** No telemetry, no update
checks, no background fetches. A feed is contacted only when you run
``cra24 feeds sync`` or pass ``--feeds`` to a command, and every client names the
host it contacts in ``cra24 feeds status``.

**Offline is a first-class mode, not a failure mode.** ``--offline`` refuses to
open a socket and answers from the cache, saying how old it is. A build machine
on a factory network is the normal case in this industry, and an incident is the
worst moment to find out your compliance tool needs the internet.

**No third-party HTTP library.** ``urllib`` from the standard library, so the
base package keeps zero runtime dependencies. A manufacturer's security review
of a tool with no dependency tree is a short conversation, and that matters more
here than the ergonomics of ``requests``.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from .. import __version__
from ..errors import Cra24Error
from ..logging import get
from .cache import Cache

log = get("feeds")

USER_AGENT = f"cra24/{__version__} (+https://github.com/cra24/cra24)"
DEFAULT_TIMEOUT = 30.0

#: Refuse a feed payload larger than this, before and after decompression.
#: The largest thing cra24 fetches is the NVD full feed, comfortably inside it.
#: Without a cap, ``resp.read()`` is however many bytes the far end feels like
#: sending, and ``gzip.decompress`` on a few hundred kilobytes of zeros is a
#: multi-gigabyte allocation. This runs unattended on an hourly timer, so an
#: out-of-memory kill is a watch that silently stopped watching.
MAX_RESPONSE_BYTES = 512 * 1024 * 1024


class FeedError(Cra24Error):
    exit_code = 8


class OfflineError(FeedError):
    """A network fetch was required but the caller asked for offline operation."""

    exit_code = 9


@dataclass
class Response:
    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def not_modified(self) -> bool:
        return self.status == 304

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except json.JSONDecodeError as exc:
            raise FeedError(f"response was not valid JSON: {exc}") from exc


def _bounded_decompress(decompressor, body: bytes) -> bytes:
    """Inflate at most :data:`MAX_RESPONSE_BYTES`, then give up.

    ``gzip.decompress`` has no ceiling, so a compressed payload the size of an
    email can ask for all the memory on the machine.
    """
    out = decompressor.decompress(body, MAX_RESPONSE_BYTES + 1)
    if len(out) > MAX_RESPONSE_BYTES:
        raise FeedError(
            f"feed payload expands past {MAX_RESPONSE_BYTES // (1024 * 1024)} MiB",
            hint="the far end is not serving what cra24 expects; check the URL "
            "before trusting anything else it returned",
        )
    return out


def _decompress(body: bytes, encoding: str, url: str) -> bytes:
    encoding = (encoding or "").lower()
    if encoding == "gzip" or url.endswith(".gz"):
        try:
            return _bounded_decompress(zlib.decompressobj(zlib.MAX_WBITS | 16), body)
        except (OSError, EOFError, zlib.error):
            # A .gz URL served already-decompressed, or a truncated stream.
            # Returning the raw bytes lets the caller's parser produce the
            # better error message.
            return body
    if encoding == "deflate":
        try:
            return _bounded_decompress(zlib.decompressobj(), body)
        except zlib.error:
            return body
    return body


class _NoDowngradeRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never from https to plaintext http.

    urllib will happily walk an https feed down onto http, which hands anyone
    on the path the ability to choose what CISA and NVD appear to say. The
    answers here end up in a regulatory filing, so a redirect that drops TLS is
    refused rather than followed.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if req.full_url.lower().startswith("https://") and newurl.lower().startswith("http://"):
            raise urllib.error.HTTPError(
                req.full_url,
                code,
                f"refusing redirect from https to plaintext http: {newurl}",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_NoDowngradeRedirect)


class HttpClient:
    """A small, polite HTTP client with conditional requests and rate limiting."""

    def __init__(
        self,
        *,
        offline: bool = False,
        timeout: float = DEFAULT_TIMEOUT,
        min_interval: float = 0.0,
        retries: int = 2,
    ) -> None:
        self.offline = offline
        self.timeout = timeout
        self.min_interval = min_interval
        self.retries = retries
        self._last_request = 0.0

    def _wait(self) -> None:
        if self.min_interval <= 0:
            return
        elapsed = time.monotonic() - self._last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: bytes | None = None,
    ) -> Response:
        if self.offline:
            raise OfflineError(
                f"offline mode: refusing to contact {urllib.parse.urlparse(url).netloc}",
                hint="drop --offline, or populate the cache with `cra24 feeds sync` "
                "on a machine that has a network and copy .cra24-cache across",
            )

        if params:
            query = urllib.parse.urlencode(
                {k: v for k, v in params.items() if v not in (None, "")}
            )
            url = f"{url}?{query}" if query else url

        request_headers = {
            "User-Agent": USER_AGENT,
            "Accept-Encoding": "gzip, deflate",
            **(headers or {}),
        }
        if data is not None:
            request_headers.setdefault("Content-Type", "application/json")

        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            self._wait()
            request = urllib.request.Request(url, data=data, headers=request_headers)
            try:
                self._last_request = time.monotonic()
                with _OPENER.open(request, timeout=self.timeout) as resp:
                    raw = resp.read(MAX_RESPONSE_BYTES + 1)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise FeedError(
                            f"{urllib.parse.urlparse(url).netloc} returned more than "
                            f"{MAX_RESPONSE_BYTES // (1024 * 1024)} MiB",
                            hint="cra24 fetches advisory data, not disk images; "
                            "check the URL before trusting the response",
                        )
                    hdrs = {k.lower(): v for k, v in resp.headers.items()}
                    body = _decompress(raw, hdrs.get("content-encoding", ""), url)
                    log.debug("GET %s -> %s (%d bytes)", url, resp.status, len(body))
                    return Response(status=resp.status, body=body, headers=hdrs)
            except urllib.error.HTTPError as exc:
                hdrs = {k.lower(): v for k, v in (exc.headers or {}).items()}
                if exc.code == 304:
                    return Response(status=304, body=b"", headers=hdrs)
                # 4xx other than rate limiting is the caller's fault; retrying
                # a malformed request just annoys the far end.
                if exc.code == 429 or exc.code >= 500:
                    last_error = exc
                    # Only sleep if there is another attempt to sleep before.
                    # Honouring a 60-second Retry-After and then giving up
                    # anyway just delays the error by a minute.
                    if attempt < self.retries:
                        backoff = self._backoff(attempt, hdrs.get("retry-after"))
                        log.warning(
                            "%s returned %s, retrying in %.1fs",
                            urllib.parse.urlparse(url).netloc,
                            exc.code,
                            backoff,
                        )
                        time.sleep(backoff)
                    continue
                raise FeedError(
                    f"{urllib.parse.urlparse(url).netloc} returned HTTP {exc.code} for {url}",
                    hint="if this is 403, the host may be blocked by an egress policy "
                    "on this machine — check with your network team rather than "
                    "routing around it",
                ) from exc
            except (urllib.error.URLError, TimeoutError) as exc:
                last_error = exc
                if attempt < self.retries:
                    backoff = self._backoff(attempt, None)
                    log.warning(
                        "%s unreachable (%s), retrying in %.1fs",
                        urllib.parse.urlparse(url).netloc,
                        exc,
                        backoff,
                    )
                    time.sleep(backoff)
                    continue

        raise FeedError(
            f"could not reach {urllib.parse.urlparse(url).netloc} after "
            f"{self.retries + 1} attempt(s): {last_error}",
            hint="use --offline to work from the cache instead",
        )

    @staticmethod
    def _backoff(attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                return min(float(retry_after), 60.0)
            except ValueError:
                pass
        return min(2.0**attempt, 30.0)

    def post_json(
        self, url: str, payload: dict[str, Any], *, headers: dict[str, str] | None = None
    ) -> Response:
        return self.get(url, headers=headers, data=json.dumps(payload).encode("utf-8"))


@dataclass
class FeedStatus:
    name: str
    host: str
    present: bool
    fetched_at: str = ""
    age_hours: float | None = None
    fresh: bool = False
    records: int | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "host": self.host,
            "present": self.present,
            "fetched_at": self.fetched_at,
            "age_hours": self.age_hours,
            "fresh": self.fresh,
            "records": self.records,
            "note": self.note,
        }


class Feed:
    """Base class for a feed client.

    Subclasses set ``name``, ``host``, ``url``, ``filename`` and ``max_age``, and
    implement :meth:`parse`. The sync-and-cache dance is the same for all of
    them and lives here.
    """

    name: str = ""
    host: str = ""
    url: str = ""
    filename: str = "data.json"
    max_age: timedelta = timedelta(hours=24)
    #: One line shown by ``cra24 feeds status`` saying what this feed is for.
    purpose: str = ""
    #: Terms the user should know about before redistributing cached data.
    terms: str = ""

    def __init__(self, cache: Cache | None = None, client: HttpClient | None = None) -> None:
        self.cache = cache or Cache()
        self.client = client or HttpClient()

    # -- subclass hook -----------------------------------------------------

    def parse(self, raw: bytes) -> Any:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- shared behaviour --------------------------------------------------

    def sync(self, *, force: bool = False) -> FeedStatus:
        """Fetch if the cache is stale, using a conditional request when we can."""
        if not force and self.cache.is_fresh(self.name, self.filename, self.max_age):
            log.info("%s is fresh, not fetching", self.name)
            return self.status()

        headers: dict[str, str] = {}
        meta = self.cache.meta(self.name, self.filename)
        if not force and self.cache.has(self.name, self.filename):
            if meta.etag:
                headers["If-None-Match"] = meta.etag
            if meta.last_modified:
                headers["If-Modified-Since"] = meta.last_modified

        response = self.client.get(self.url, headers=headers)
        if response.not_modified:
            log.info("%s unchanged upstream", self.name)
            self.cache.touch_revalidated(self.name, self.filename)
            return self.status()

        self.cache.write(
            self.name,
            self.filename,
            response.body,
            url=self.url,
            etag=response.headers.get("etag", ""),
            last_modified=response.headers.get("last-modified", ""),
        )
        log.info("%s synced (%d bytes)", self.name, len(response.body))
        return self.status()

    def load(self, *, sync_if_stale: bool = False) -> Any:
        """Parsed feed data, from the cache.

        Never fetches unless asked. A triage run that silently reached out to the
        internet would be one you could not reproduce later.
        """
        if sync_if_stale and not self.cache.is_fresh(self.name, self.filename, self.max_age):
            self.sync()
        return self.parse(self.cache.read_bytes(self.name, self.filename))

    def available(self) -> bool:
        return self.cache.has(self.name, self.filename)

    def status(self) -> FeedStatus:
        meta = self.cache.meta(self.name, self.filename)
        age = meta.age()
        present = self.cache.has(self.name, self.filename)
        records = None
        if present:
            try:
                data = self.parse(self.cache.read_bytes(self.name, self.filename))
                records = len(data) if hasattr(data, "__len__") else None
            except Exception:
                records = None
        return FeedStatus(
            name=self.name,
            host=self.host,
            present=present,
            fetched_at=meta.fetched_at,
            age_hours=round(age.total_seconds() / 3600, 1) if age else None,
            fresh=self.cache.is_fresh(self.name, self.filename, self.max_age),
            records=records,
            note=self.purpose,
        )
