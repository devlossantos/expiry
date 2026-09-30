"""Minimal Microsoft Graph client using the client-credentials flow (app-only)."""

from __future__ import annotations

import time
from typing import Any, Iterator

import msal
import requests

from expiry.config import Config


class GraphError(RuntimeError):
    pass


class GraphClient:
    def __init__(self, cfg: Config):
        tenant = (cfg.get("entra.tenant_id") or "").strip()
        client_id = (cfg.get("entra.client_id") or "").strip()
        secret = cfg.get("entra.client_secret") or ""
        cert_path = cfg.get("entra.certificate_path") or ""
        if not tenant or not client_id:
            raise GraphError("entra.tenant_id and entra.client_id must be set in the config")
        if cert_path:
            from expiry.certauth import CertError, load_credential
            try:
                credential: Any = load_credential(
                    cert_path, cfg.get("entra.certificate_thumbprint") or "").msal_credential()
            except CertError as exc:
                raise GraphError(f"entra.certificate_path: {exc}") from exc
        elif secret:
            credential = secret
        else:
            raise GraphError("set entra.client_secret or entra.certificate_path in the config")

        graph_url = (cfg.get("entra.graph_url") or "https://graph.microsoft.com").rstrip("/")
        authority = f"{(cfg.get('entra.authority_host') or 'https://login.microsoftonline.com').rstrip('/')}/{tenant}"
        self.base = f"{graph_url}/v1.0"
        self.scopes = [f"{graph_url}/.default"]
        self.app = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=credential)
        self.session = requests.Session()

    def token(self) -> str:
        result = self.app.acquire_token_for_client(scopes=self.scopes)
        if "access_token" not in result:
            desc = (result.get("error_description") or "").splitlines()
            raise GraphError(f"token request failed: {result.get('error')}: {desc[0] if desc else ''}")
        return result["access_token"]

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        if not url.startswith("http"):
            url = self.base + url
        for attempt in range(5):
            headers = {"Authorization": f"Bearer {self.token()}", "Accept": "application/json"}
            resp = self.session.request(method, url, headers=headers, timeout=60, **kwargs)
            if resp.status_code in (429, 502, 503, 504) and attempt < 4:
                try:
                    wait = int(resp.headers.get("Retry-After", ""))
                except ValueError:
                    wait = 2 ** attempt
                time.sleep(min(wait, 60))
                continue
            if resp.status_code >= 400:
                raise GraphError(_describe_error(method, url, resp))
            return resp
        raise GraphError(f"{method} {url}: giving up after retries")

    def get_all(self, path: str, params: dict | None = None) -> Iterator[dict]:
        url: str | None = path
        while url:
            data = self.request("GET", url, params=params).json()
            yield from data.get("value", [])
            url = data.get("@odata.nextLink")
            params = None  # nextLink already carries the query

    def send_mail(self, sender: str, to: list[str], subject: str, html: str) -> None:
        body = {
            "message": {
                "subject": subject,
                "body": {"contentType": "HTML", "content": html},
                "toRecipients": [{"emailAddress": {"address": a}} for a in to],
            },
            "saveToSentItems": False,
        }
        self.request("POST", f"/users/{sender}/sendMail", json=body)


def _describe_error(method: str, url: str, resp: requests.Response) -> str:
    try:
        err = resp.json().get("error", {})
        msg = f"{err.get('code')}: {err.get('message')}"
    except ValueError:
        msg = resp.text[:200]
    hint = ""
    if resp.status_code == 403:
        hint = " (hint: the app registration is missing an API permission or admin consent was not granted)"
    elif resp.status_code == 401:
        hint = " (hint: check tenant_id / client_id / secret)"
    path = url.split("/v1.0", 1)[-1].split("?", 1)[0]
    return f"{method} {path} -> HTTP {resp.status_code} {msg}{hint}"
