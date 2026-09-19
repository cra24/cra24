# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Vulnerability feed clients.

cra24 makes no network call you did not ask for. Nothing here runs unless you
invoke ``cra24 feeds sync`` or pass ``--feeds`` to a command, every client names
the host it contacts, and ``--offline`` refuses to open a socket at all.
"""

from .base import Feed, FeedError, FeedStatus, HttpClient, OfflineError
from .cache import Cache, CacheError
from .epss import EpssFeed, EpssScore
from .euvd import EuvdFeed, EuvdRecord
from .kev import KevEntry, KevFeed
from .nvd import NvdFeed, NvdRecord
from .osv import OsvFeed, OsvRecord
from .registry import Enrichment, FeedSet, enrich

__all__ = [
    "Cache",
    "CacheError",
    "Enrichment",
    "EpssFeed",
    "EpssScore",
    "EuvdFeed",
    "EuvdRecord",
    "Feed",
    "FeedError",
    "FeedSet",
    "FeedStatus",
    "HttpClient",
    "KevEntry",
    "KevFeed",
    "NvdFeed",
    "NvdRecord",
    "OfflineError",
    "OsvFeed",
    "OsvRecord",
    "enrich",
]
