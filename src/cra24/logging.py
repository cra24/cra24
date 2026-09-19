# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Logging setup.

Two modes. Humans get terse lines on stderr. Machines get JSON, because when this
runs in a watch daemon at 3am the log is the only witness.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone

LOGGER_NAME = "cra24"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in getattr(record, "extra_fields", {}).items():
            payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, sort_keys=True, default=str)


def configure(verbosity: int = 0, json_logs: bool | None = None) -> logging.Logger:
    """Configure and return the package logger.

    ``CRA24_LOG_JSON=1`` in the environment forces JSON regardless of the caller.
    """
    if json_logs is None:
        json_logs = os.environ.get("CRA24_LOG_JSON", "") not in ("", "0", "false")

    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        JsonFormatter() if json_logs else logging.Formatter("%(levelname)s: %(message)s")
    )
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def get(name: str = "") -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)
