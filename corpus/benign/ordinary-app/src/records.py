"""Ordinary application code: no dynamic execution, no encoded data."""
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable


@dataclass(frozen=True)
class Record:
    identifier: str
    created_at: datetime
    payload: dict

    def age_in_days(self, now: datetime) -> int:
        return (now - self.created_at).days


def most_recent(records: Iterable[Record], limit: int = 10) -> list[Record]:
    return sorted(records, key=lambda r: r.created_at, reverse=True)[:limit]


def group_by_day(records: Iterable[Record]) -> dict[str, list[Record]]:
    grouped: dict[str, list[Record]] = {}
    for record in records:
        grouped.setdefault(record.created_at.strftime("%Y-%m-%d"), []).append(record)
    return grouped
