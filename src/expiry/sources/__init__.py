"""Source registry and the sync routine that writes source items into the store.

To add a new source (AWS IAM keys, Key Vault, GitHub tokens, ...): implement the `Source`
protocol in a new module and register it in `build_sources`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from expiry.config import Config
from expiry.db import Store
from expiry.sources.base import FetchResult, Item, Source

log = logging.getLogger(__name__)

__all__ = ["FetchResult", "Item", "Source", "SyncResult", "build_sources", "sync_source", "run_sync"]

KNOWN_SOURCES = ("entra", "ssl")


@dataclass
class SyncResult:
    source: str
    found: int = 0
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    ignored: int = 0
    archived: int = 0
    errors: list[str] = field(default_factory=list)
    failed: bool = False
    items: list[Item] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "found": self.found, "created": self.created, "updated": self.updated, "unchanged": self.unchanged,
            "ignored": self.ignored, "archived": self.archived, "errors": self.errors, "failed": self.failed,
        }


def build_sources(cfg: Config, store: Store, only: str | None = None) -> dict[str, Source]:
    sources: dict[str, Source] = {}
    if cfg.get("sources.entra.enabled") and only in (None, "entra"):
        from expiry.sources.entra import EntraSource
        sources["entra"] = EntraSource(cfg)
    if cfg.get("sources.ssl.enabled") and only in (None, "ssl"):
        from expiry.sources.sslcert import SslSource
        sources["ssl"] = SslSource(cfg, store)
    return sources


def sync_source(source: Source, store: Store, dry_run: bool = False) -> SyncResult:
    res = SyncResult(source.name)
    actor = f"sync:{source.name}"
    try:
        fetched = source.fetch()
    except Exception as exc:  # noqa: BLE001
        log.exception("sync %s failed", source.name)
        res.errors.append(str(exc))
        res.failed = True
        return res
    res.found = len(fetched.items)
    res.errors.extend(fetched.errors)
    res.items = fetched.items
    if dry_run:
        return res
    for item in fetched.items:
        outcome = store.upsert_external(source.name, item.external_id, item.name, item.expires_on, item.meta,
                                        actor, notes=item.notes)
        setattr(res, outcome, getattr(res, outcome) + 1)
    keep = {i.external_id for i in fetched.items} | fetched.keep_ids
    res.archived = len(store.archive_missing(source.name, keep, actor))
    return res


def run_sync(cfg: Config, store: Store, only: str | None = None, dry_run: bool = False) -> list[SyncResult]:
    results = [sync_source(src, store, dry_run) for src in build_sources(cfg, store, only).values()]
    if not dry_run:
        from expiry import health
        from expiry.util import utcnow_iso
        store.kv_set("last_sync", {"at": utcnow_iso(), "results": {r.source: r.summary() for r in results}})
        for r in results:  # a whole-source failure counts; one unreachable SSL host does not
            health.record(store, f"sync:{r.source}", not r.failed, "; ".join(r.errors))
    return results
