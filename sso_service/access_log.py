"""Append-only JSONL access log: which app or browser called what, from where, with which outcome.

Session tokens, token hashes, OAuth codes and states are never written.
Each line is opened, appended and closed, so an external logrotate rename needs no signal.
"""

from __future__ import annotations

import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AccessLog:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self.last_error: str | None = None

    @property
    def healthy(self) -> bool:
        return self.last_error is None

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(
            {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"), **record},
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
                self.last_error = None
            except OSError as exc:
                # Degrade explicitly: journald gets the line, /health reports access_log=degraded.
                self.last_error = type(exc).__name__
                print(f"[access-log-degraded] {self.last_error}: {line}", file=sys.stderr, flush=True)
