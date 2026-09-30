"""Microsoft Entra ID source: client secrets and certificates of app registrations (and optionally
enterprise applications / service principals, e.g. SAML signing certificates)."""

from __future__ import annotations

import fnmatch
import logging
from datetime import timedelta
from zoneinfo import ZoneInfo

from expiry.config import Config
from expiry.graph import GraphClient, GraphError
from expiry.sources.base import FetchResult, Item
from expiry.util import parse_graph_datetime, today

log = logging.getLogger(__name__)

SELECT = "id,appId,displayName,passwordCredentials,keyCredentials"
APP_PORTAL = "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/{appId}"
SP_PORTAL = "https://portal.azure.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/{id}/appId/{appId}"


class EntraSource:
    name = "entra"

    def __init__(self, cfg: Config, graph: GraphClient | None = None):
        self.cfg = cfg
        self.opts = cfg.get("sources.entra") or {}
        self.tz = ZoneInfo(cfg.timezone)
        self._graph = graph

    @property
    def graph(self) -> GraphClient:
        if self._graph is None:
            self._graph = GraphClient(self.cfg)
        return self._graph

    def fetch(self) -> FetchResult:
        result = FetchResult()
        cutoff = today(self.cfg.timezone) - timedelta(days=int(self.opts.get("ignore_expired_after_days", 30)))

        objects = [("application", o) for o in self.graph.get_all("/applications", {"$select": SELECT, "$top": "999"})]
        if self.opts.get("include_service_principals"):
            sps = self.graph.get_all(
                "/servicePrincipals", {"$select": SELECT + ",servicePrincipalType", "$top": "999"}
            )
            objects += [
                ("servicePrincipal", o)
                for o in sps
                if o.get("servicePrincipalType") == "Application"
                and (o.get("passwordCredentials") or o.get("keyCredentials"))
            ]

        for kind, obj in objects:
            if not self._wanted(obj):
                continue
            items = self._items_for(kind, obj, cutoff)
            if items and self.opts.get("notify_owners"):
                try:
                    owners = self._owners(kind, obj["id"])
                except GraphError as exc:
                    result.errors.append(f"owners of {obj.get('displayName')}: {exc}")
                    owners = []
                for it in items:
                    it.meta["owners"] = owners
            result.items.extend(items)
        return result

    def _wanted(self, obj: dict) -> bool:
        name = (obj.get("displayName") or "").lower()
        app_id = (obj.get("appId") or "").lower()
        include = [p.lower() for p in self.opts.get("include") or []]
        exclude = [p.lower() for p in self.opts.get("exclude") or []]
        matches = lambda pats: any(fnmatch.fnmatch(name, p) or app_id == p for p in pats)  # noqa: E731
        if include and not matches(include):
            return False
        return not matches(exclude)

    def _items_for(self, kind: str, obj: dict, cutoff) -> list[Item]:
        items: list[Item] = []
        prefix = "app" if kind == "application" else "sp"
        display = obj.get("displayName") or obj.get("appId")
        portal = (APP_PORTAL if kind == "application" else SP_PORTAL).format(**obj)
        base_meta = {
            "object_type": kind,
            "object_id": obj.get("id"),
            "app_id": obj.get("appId"),
            "app_name": display,
            "portal_url": portal,
        }

        creds: list[tuple[str, dict]] = []
        if self.opts.get("include_secrets", True):
            creds += [("secret", c) for c in obj.get("passwordCredentials") or []]
        if self.opts.get("include_certificates", True):
            # SAML/SP certs appear twice (Sign + Verify) with the same thumbprint: keep one.
            seen: set[tuple] = set()
            for c in sorted(obj.get("keyCredentials") or [], key=lambda c: c.get("keyId") or ""):
                key = (c.get("customKeyIdentifier"), c.get("endDateTime"))
                if key in seen:
                    continue
                seen.add(key)
                creds.append(("certificate", c))

        for cred_kind, c in creds:
            if not c.get("endDateTime") or not c.get("keyId"):
                continue
            expires_on = parse_graph_datetime(c["endDateTime"]).astimezone(self.tz).date()
            if expires_on < cutoff:
                continue
            label = c.get("displayName") or (f"{c['hint']}***" if c.get("hint") else c["keyId"][:8])
            short = "secret" if cred_kind == "secret" else "cert"
            items.append(
                Item(
                    external_id=f"entra:{prefix}:{obj['id']}:{cred_kind}:{c['keyId']}",
                    name=f"{display} [{short}: {label}]",
                    expires_on=expires_on,
                    meta={**base_meta, "credential_type": cred_kind, "key_id": c["keyId"], "label": label},
                )
            )
        return items

    def _owners(self, kind: str, object_id: str) -> list[str]:
        coll = "applications" if kind == "application" else "servicePrincipals"
        owners = []
        for o in self.graph.get_all(f"/{coll}/{object_id}/owners", {"$select": "mail,userPrincipalName"}):
            addr = o.get("mail") or o.get("userPrincipalName") or ""
            if "@" in addr and "#EXT#" not in addr:
                owners.append(addr)
        return owners
