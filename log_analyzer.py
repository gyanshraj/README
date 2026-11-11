"""Web server access-log parsing and authentication surge detection."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/\S+)?" '
    r"(?P<status>\d{3}) (?P<size>\S+)"
)
AUTH_PATH_PATTERN = re.compile(r"/(?:login|signin|authenticate)(?:/|$)", re.IGNORECASE)


@dataclass(frozen=True)
class LogEntry:
    ip: str
    method: str
    path: str
    status: int
    size: int | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def parse_log_line(line: str) -> LogEntry | None:
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    size = None if match["size"] == "-" else int(match["size"])
    return LogEntry(
        ip=match["ip"],
        method=match["method"],
        path=match["path"],
        status=int(match["status"]),
        size=size,
    )


def read_log(path: str | Path) -> Iterable[LogEntry]:
    with Path(path).open(encoding="utf-8") as log_file:
        for line in log_file:
            entry = parse_log_line(line)
            if entry is not None:
                yield entry


def find_authentication_alerts(
    entries: Iterable[LogEntry], threshold: int
) -> list[dict[str, object]]:
    """Return IPs with at least ``threshold`` authentication requests."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    counts = Counter(
        entry.ip
        for entry in entries
        if AUTH_PATH_PATTERN.search(entry.path) is not None
    )
    return [
        {"ip": ip, "authentication_requests": count, "alert": True}
        for ip, count in sorted(counts.items())
        if count >= threshold
    ]
