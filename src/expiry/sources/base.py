"""Source plugin contract. A source discovers expiring things and returns them as Items."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Protocol


@dataclass
class Item:
    external_id: str  # stable, unique id, e.g. "entra:app:<objectId>:secret:<keyId>"
    name: str
    expires_on: date
    meta: dict = field(default_factory=dict)
    notes: str = ""  # only used when the reminder is first created


@dataclass
class FetchResult:
    items: list[Item] = field(default_factory=list)
    # Non-fatal problems (e.g. one host unreachable). Reported, but the sync still counts as complete.
    errors: list[str] = field(default_factory=list)
    # External ids that must NOT be archived even though they were not returned this time
    # (e.g. an SSL target that was unreachable on this run).
    keep_ids: set[str] = field(default_factory=set)


class Source(Protocol):
    name: str

    def fetch(self) -> FetchResult:
        """Return every item the source currently knows about. Raise on total failure."""
        ...
