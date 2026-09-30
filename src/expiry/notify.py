"""Rendering (Jinja2) and delivery channels: SMTP, Microsoft Graph sendMail, webhooks."""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass
from datetime import date
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from importlib import resources
from pathlib import Path
from typing import Any

import jinja2
import requests

from expiry import __version__
from expiry.config import Config
from expiry.db import Reminder
from expiry.util import DEFAULT_DATE_FORMAT, describe_days, format_date


def stage_label(stage: int) -> str:
    if stage == 0:
        return "expires today / expired"
    if stage == 1:
        return "1 day before"
    if stage % 7 == 0 and stage < 30:
        return f"{stage // 7} week{'s' if stage > 7 else ''} before"
    if stage == 30:
        return "1 month before"
    return f"{stage} days before"


def severity(days_left: int) -> str:
    if days_left <= 1:
        return "critical"
    if days_left <= 14:
        return "warning"
    return "notice"


def item_context(r: Reminder, today: date, stage: int | None = None,
                 date_format: str = DEFAULT_DATE_FORMAT) -> dict[str, Any]:
    days = r.days_left(today)
    return {
        "id": r.id,
        "name": r.name,
        "expires_on": format_date(r.expires_on, date_format),
        "expires_on_iso": r.expires_on.isoformat(),
        "expires_on_long": r.expires_on.strftime("%A, %d %B %Y"),
        "days_left": days,
        "when": describe_days(days),
        "expired": days < 0,
        "severity": severity(days),
        "stage": stage,
        "stage_label": stage_label(stage) if stage is not None else "",
        "notes": r.notes,
        "source": r.source,
        "url": r.meta.get("portal_url", ""),
        "meta": r.meta,
    }


@dataclass
class Rendered:
    subject: str
    html: str
    text: str


class Renderer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        template_file = cfg.get("email.template_file")
        if template_file:
            p = Path(template_file)
            loader: jinja2.BaseLoader = jinja2.FileSystemLoader(str(p.parent))
            self.template_name = p.name
        else:
            src = resources.files("expiry").joinpath("templates/default.html.j2").read_text(encoding="utf-8")
            loader = jinja2.DictLoader({"default.html.j2": src})
            self.template_name = "default.html.j2"
        self.html_env = jinja2.Environment(loader=loader, autoescape=True, undefined=jinja2.ChainableUndefined)
        self.text_env = jinja2.Environment(autoescape=False, undefined=jinja2.ChainableUndefined)

    def render(self, items: list[dict], today: date, certificate: dict | None = None) -> Rendered:
        ctx = {"items": items, "item": items[0] if items else {}, "today": format_date(today, self.cfg.date_format),
               "certificate": certificate,
               "count": len(items), "version": __version__}
        subject = self.text_env.from_string(self.cfg.get("email.subject") or "").render(**ctx).strip()
        subject = " ".join(subject.split())  # no newlines in headers
        html = self.html_env.get_template(self.template_name).render(**ctx)
        return Rendered(subject, html, render_text(items))


def render_text(items: list[dict]) -> str:
    lines = ["The following items need attention:", ""]
    for it in items:
        lines.append(f"* {it['name']}")
        lines.append(f"  Expires: {it['expires_on']} ({it['when']})")
        if it.get("notes"):
            lines.append(f"  Notes:   {it['notes']}")
        if it.get("url"):
            lines.append(f"  Link:    {it['url']}")
        lines.append(f"  ID:      {it['id']}  (source: {it['source']})")
        lines.append("")
    lines.append(f"-- sent by expiry {__version__}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------- email


class EmailSender:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.transport = cfg.get("email.transport", "smtp")

    def send(self, to: list[str], msg: Rendered) -> None:
        if self.transport == "graph":
            from expiry.graph import GraphClient
            GraphClient(self.cfg).send_mail(self.cfg.get("email.graph.sender"), to, msg.subject, msg.html)
        else:
            self._send_smtp(to, msg)

    def _send_smtp(self, to: list[str], msg: Rendered) -> None:
        c = self.cfg.get("email.smtp")
        em = EmailMessage()
        em["Subject"] = msg.subject
        em["From"] = self.cfg.get("email.from")
        em["To"] = ", ".join(to)
        em["Date"] = formatdate(localtime=True)
        em["Message-ID"] = make_msgid(domain="expiry.local")
        em.set_content(msg.text)
        em.add_alternative(msg.html, subtype="html")
        host, port, timeout = c["host"], int(c.get("port") or 587), int(c.get("timeout") or 30)
        security = c.get("security", "starttls")
        context = ssl.create_default_context()
        if security == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)
        with server:
            server.ehlo()
            if security == "starttls":
                server.starttls(context=context)
                server.ehlo()
            if c.get("username"):
                server.login(c["username"], c.get("password") or "")
            server.send_message(em)


# ---------------------------------------------------------------------------- webhooks


def webhook_payload(fmt: str, items: list[dict]) -> dict:
    lines = [f"{it['name']} — expires {it['expires_on']} ({it['when']})" + (f" — {it['notes']}" if it["notes"] else "")
             for it in items]
    title = f"Expiry: {len(items)} item(s) need attention"
    extra = {"items": [{k: v for k, v in it.items() if k != "meta"} for it in items]}
    return message_payload(fmt, title, lines, extra)


def message_payload(fmt: str, title: str, lines: list[str], extra: dict | None = None) -> dict:
    """A title + lines message in the shape each webhook format expects."""
    if fmt == "slack":
        return {"text": f"*{title}*\n" + "\n".join(f"• {l}" for l in lines)}
    if fmt == "teams":
        # Adaptive card, accepted by Teams "Workflows" (Power Automate) incoming webhooks.
        body = [{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "text": title, "wrap": True}]
        body += [{"type": "TextBlock", "text": f"- {l}", "wrap": True, "spacing": "Small"} for l in lines]
        return {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "type": "AdaptiveCard", "version": "1.4", "body": body},
            }],
        }
    return {"title": title, "text": "\n".join(lines), **(extra or {})}


def send_webhook(hook: dict, items: list[dict]) -> None:
    resp = requests.post(hook["url"], json=webhook_payload(hook.get("format", "generic"), items), timeout=20)
    resp.raise_for_status()


def send_message_webhook(hook: dict, title: str, lines: list[str]) -> None:
    resp = requests.post(hook["url"], json=message_payload(hook.get("format", "generic"), title, lines), timeout=20)
    resp.raise_for_status()


def send_message(cfg: Config, recipients: list[str], subject: str, lines: list[str],
                 email_sender=None, webhook_sender=None) -> list[str]:
    """Send a plain informational message (alerts, scan results) by email and to every webhook.
    Returns the channels that delivered it."""
    import html as _html
    import logging

    log = logging.getLogger(__name__)
    delivered = []
    if cfg.get("email.enabled") and recipients:
        body = "".join(f'<p style="margin:0 0 8px 0">{_html.escape(line)}</p>' for line in lines)
        msg = Rendered(subject, f'<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px">{body}</div>',
                       "\n".join(lines))
        try:
            (email_sender or EmailSender(cfg)).send(recipients, msg)
            delivered.append("email")
        except Exception as exc:  # noqa: BLE001
            log.error("could not email '%s': %s", subject, exc)
    for hook in cfg.get("notify.webhooks") or []:
        try:
            (webhook_sender or send_message_webhook)(hook, subject, lines[:-1] if len(lines) > 1 else lines)
            delivered.append(f"webhook:{hook.get('format', 'generic')}")
        except Exception as exc:  # noqa: BLE001
            log.error("could not send '%s' to webhook: %s", subject, exc)
    return delivered
