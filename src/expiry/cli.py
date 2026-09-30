"""expiry command line interface."""

from __future__ import annotations

import csv
import io
import json
import os
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import click
import yaml
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from expiry import __version__
from expiry.config import Config, load_config, masked, validate
from expiry.db import Reminder, Store
from expiry.util import (actor, describe_days, format_date, is_email, parse_date, parse_host_port, split_emails,
                         today)

console = Console(highlight=False)
err = Console(stderr=True, highlight=False)

ALIASES = {
    "ls": "list", "new": "add", "update": "edit", "modify": "edit", "info": "show", "get": "show",
    "remove": "rm", "delete": "rm", "del": "rm", "log": "audit", "cert": "ssl", "tls": "ssl",
}
SOURCES = ("manual", "entra", "ssl")


class AliasedGroup(click.Group):
    def get_command(self, ctx: click.Context, cmd_name: str):
        return super().get_command(ctx, ALIASES.get(cmd_name, cmd_name))

    def resolve_command(self, ctx: click.Context, args: list[str]):
        _, cmd, rest = super().resolve_command(ctx, args)
        return cmd.name if cmd else None, cmd, rest


class App:
    def __init__(self, config_path: str | None):
        self.config_path = config_path
        self._cfg: Config | None = None
        self._store: Store | None = None

    @property
    def cfg(self) -> Config:
        if self._cfg is None:
            try:
                self._cfg = load_config(self.config_path)
            except Exception as exc:  # noqa: BLE001
                raise click.ClickException(f"cannot load config: {exc}") from exc
        return self._cfg

    @property
    def store(self) -> Store:
        if self._store is None:
            try:
                self._store = Store(self.cfg.db_path)
            except Exception as exc:  # noqa: BLE001
                raise click.ClickException(f"cannot open database {self.cfg.db_path}: {exc}") from exc
        return self._store

    @property
    def today(self) -> date:
        return today(self.cfg.timezone)

    def fmt(self, d: date | str | None) -> str:
        if not d:
            return "-"
        if isinstance(d, str):
            d = date.fromisoformat(d)
        return format_date(d, self.cfg.date_format)

    def parse(self, value: str) -> date:
        try:
            return parse_date(value, self.today, self.cfg.date_format)
        except ValueError as exc:
            raise click.BadParameter(str(exc)) from exc

    def reminder(self, rid: int) -> Reminder:
        r = self.store.get(rid)
        if r is None:
            raise click.ClickException(f"no reminder with id {rid} (see `expiry list --all`)")
        return r

    def close(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None


pass_app = click.make_pass_decorator(App)


# ============================================================================ helpers


def days_text(days: int, muted: bool = False) -> Text:
    if days < 0:
        t = Text(f"EXPIRED {-days}d ago", style="bold red")
    elif days == 0:
        t = Text("TODAY", style="bold red")
    elif days <= 1:
        t = Text(str(days), style="bold red")
    elif days <= 14:
        t = Text(str(days), style="dark_orange")
    elif days <= 30:
        t = Text(str(days), style="yellow")
    else:
        t = Text(str(days), style="green")
    if muted:
        t.append(" (muted)", style="dim")
    return t


def reminders_table(reminders: list[Reminder], ref: date, fmt: str, show_status: bool = False) -> Table:
    table = Table(box=box.SIMPLE_HEAD, pad_edge=False, header_style="bold")
    table.add_column("ID", justify="right", style="cyan", no_wrap=True)
    table.add_column("Name", overflow="fold", ratio=3)
    table.add_column("Expires", no_wrap=True)
    table.add_column("Days left", justify="right", no_wrap=True)
    table.add_column("Source", no_wrap=True)
    if show_status:
        table.add_column("Status", no_wrap=True)
    table.add_column("Notes", overflow="fold", ratio=2, style="dim")
    for r in reminders:
        row: list[Any] = [str(r.id), Text(r.name), format_date(r.expires_on, fmt), days_text(r.days_left(ref), r.muted),
                          r.source]
        if show_status:
            row.append(Text(r.status, style="" if r.status == "active" else "dim"))
        row.append(Text(r.notes))
        table.add_row(*row)
    return table


def parse_emails_arg(values: tuple[str, ...] | list[str]) -> list[str]:
    emails = split_emails(",".join(values))
    bad = [e for e in emails if not is_email(e)]
    if bad:
        raise click.BadParameter(f"invalid email address: {', '.join(bad)}")
    return emails


def ok(msg: str) -> None:
    console.print(f"[green]✔[/green] {msg}")


def warn(msg: str) -> None:
    err.print(f"[yellow]![/yellow] {msg}")


def print_json(data: Any) -> None:
    click.echo(json.dumps(data, indent=2, default=str))


def local_time(iso: str | None, cfg: Config) -> str:
    if not iso:
        return "never"
    try:
        from zoneinfo import ZoneInfo
        dt = datetime.fromisoformat(iso)
        return dt.astimezone(ZoneInfo(cfg.timezone)).strftime(f"{cfg.date_format} %H:%M %Z")
    except ValueError:
        return iso


# ============================================================================ root


@click.group(cls=AliasedGroup, context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 100})
@click.option("-c", "--config", "config_path", type=click.Path(dir_okay=False),
              help="Config file. Default: $EXPIRY_CONFIG, /config/config.yaml, /etc/expiry/config.yaml.")
@click.version_option(__version__, "-V", "--version", prog_name="expiry")
@click.pass_context
def cli(ctx: click.Context, config_path: str | None) -> None:
    """Track expiring secrets, certificates and anything else, and get reminded
    30 days, 14 days and 1 day before they expire.

    \b
    Reminders
      expiry list                          List reminders with days left
      expiry add NAME DD/MM/YYYY [NOTES]   Add a reminder (also 2026-12-31, +90d, +6m, +1y)
      expiry show ID                       Show details and notification schedule
      expiry edit ID [--date ...]          Edit a reminder (interactive with no options)
      expiry rm ID [ID ...]                Remove reminder(s)
    \b
    SSL certificates
      expiry ssl add HOST[:PORT]           Track the certificate served by a domain or IP
      expiry ssl list | rm | check | discover | scan
    \b
    Sync & notifications
      expiry sync                          Pull expiry dates from Entra ID / SSL now
      expiry check                         Send due notifications now (--dry-run to preview)
      expiry test-notify                   Send a test email / webhook
      expiry status | history | audit      Service status, sent notifications, change log
    \b
    Admin
      expiry config show | check           Show (masked) or validate the configuration
      expiry backup create | list | restore  Database backups (automatic nightly by default)
      expiry entra cert-create | cert-show   Certificate login for the Entra app (instead of a secret)
      expiry export | import               Export / bulk-load reminders (JSON or CSV)

    Run `expiry COMMAND --help` for details, or `man expiry`.
    """
    app = App(config_path)
    ctx.obj = app
    ctx.call_on_close(app.close)


@cli.command("help")
@click.argument("command", nargs=-1)
@click.pass_context
def help_cmd(ctx: click.Context, command: tuple[str, ...]) -> None:
    """Show help for expiry or for a COMMAND, for example `expiry help ssl add`."""
    group: click.Command = cli
    info_ctx = click.Context(cli, info_name="expiry")
    for name in command:
        if not isinstance(group, click.Group):
            break
        sub = group.get_command(info_ctx, name)
        if sub is None:
            raise click.UsageError(f"unknown command: {' '.join(command)}")
        info_ctx = click.Context(sub, info_name=sub.name, parent=info_ctx)
        group = sub
    click.echo(group.get_help(info_ctx))


# ============================================================================ reminders


@cli.command("list")
@click.option("-a", "--all", "show_all", is_flag=True, help="Include archived and ignored reminders.")
@click.option("-s", "--source", type=click.Choice(SOURCES), help="Only reminders from this source.")
@click.option("-w", "--within", type=int, metavar="DAYS", help="Only items expiring within DAYS days (plus expired).")
@click.option("-e", "--expired", "only_expired", is_flag=True, help="Only expired items.")
@click.option("-q", "--search", metavar="TEXT", help="Filter by text in name or notes.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@pass_app
def list_cmd(app: App, show_all: bool, source: str | None, within: int | None, only_expired: bool,
             search: str | None, as_json: bool) -> None:
    """List reminders, soonest first, with the number of days left."""
    ref = app.today
    items = app.store.list(statuses=None if show_all else ("active",), source=source, search=search)
    if within is not None:
        items = [r for r in items if r.days_left(ref) <= within]
    if only_expired:
        items = [r for r in items if r.days_left(ref) < 0]
    if as_json:
        print_json([r.to_dict(ref) for r in items])
        return
    if not items:
        console.print("No reminders found." + ("" if show_all else " Add one with: expiry add NAME DD/MM/YYYY [NOTES]"))
        return
    console.print(reminders_table(items, ref, app.cfg.date_format, show_status=show_all))
    expired = sum(1 for r in items if r.days_left(ref) < 0)
    soon = sum(1 for r in items if 0 <= r.days_left(ref) <= 30)
    parts = [f"{len(items)} reminder{'s' if len(items) != 1 else ''}"]
    if soon:
        parts.append(f"[yellow]{soon} expiring within 30 days[/yellow]")
    if expired:
        parts.append(f"[red]{expired} expired[/red]")
    console.print(" · ".join(parts) + f"   [dim](today: {app.fmt(ref)}, {app.cfg.timezone})[/dim]")


@cli.command()
@click.argument("name")
@click.argument("date_str", metavar="DATE")
@click.argument("notes", nargs=-1)
@click.option("-n", "--notes", "notes_opt", metavar="TEXT", help="Notes (alternative to trailing NOTES words).")
@click.option("--notify", multiple=True, metavar="EMAIL",
              help="Extra recipient for this reminder only (repeatable or comma separated).")
@click.option("--mute", is_flag=True, help="Track it but do not send notifications.")
@click.option("--json", "as_json", is_flag=True, help="Output the created reminder as JSON.")
@pass_app
def add(app: App, name: str, date_str: str, notes: tuple[str, ...], notes_opt: str | None,
        notify: tuple[str, ...], mute: bool, as_json: bool) -> None:
    """Add a reminder.

    \b
    DATE is in the configured date_format (default DD/MM/YYYY, e.g. 31/03/2027),
    or YYYY-MM-DD, or relative to today: +30d, +2w, +6m, +1y.
    \b
    Examples:
      expiry add "Payroll API cert" 31/03/2027
      expiry add github-pat +90d rotate in GitHub settings
      expiry add "Domain example.com" 2027-01-15 --notes "renew at registrar" --notify it@example.com
    """
    ref = app.today
    expires = app.parse(date_str)
    emails = parse_emails_arg(notify)
    note_text = notes_opt if notes_opt is not None else " ".join(notes)
    if not name.strip():
        raise click.BadParameter("name cannot be empty")
    dupes = [r for r in app.store.list() if r.name.lower() == name.strip().lower()]
    r = app.store.add(name.strip(), expires, actor(), notes=note_text, notify=emails)
    if mute:
        r = app.store.update(r.id, actor(), muted=True)
    if as_json:
        print_json(r.to_dict(ref))
        return
    ok(f"Added [cyan]#{r.id}[/cyan] {escape(r.name)} — expires {app.fmt(r.expires_on)} ({describe_days(r.days_left(ref))})")
    if expires < ref:
        warn("that date is in the past; the reminder is already expired")
    if dupes:
        warn(f"another reminder has the same name: {', '.join('#' + str(d.id) for d in dupes)}")


@cli.command()
@click.argument("rid", metavar="ID", type=int)
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@pass_app
def show(app: App, rid: int, as_json: bool) -> None:
    """Show all details of a reminder, its notification schedule and history."""
    r = app.reminder(rid)
    ref = app.today
    history = app.store.history(limit=20, rid=rid)
    if as_json:
        d = r.to_dict(ref)
        d["notifications"] = [dict(h) for h in history]
        print_json(d)
        return
    t = Table(box=None, show_header=False, pad_edge=False)
    t.add_column(style="bold", no_wrap=True)
    t.add_column(overflow="fold")
    t.add_row("ID", str(r.id))
    t.add_row("Name", Text(r.name))
    t.add_row("Expires", f"{app.fmt(r.expires_on)} ({r.expires_on.strftime('%A')})")
    t.add_row("Days left", days_text(r.days_left(ref), r.muted))
    t.add_row("Status", r.status)
    t.add_row("Source", r.source + (f"  ({r.external_id})" if r.external_id else ""))
    t.add_row("Notes", Text(r.notes or "-"))
    t.add_row("Recipients", Text(", ".join(recipient_list(app.cfg, r)) or "-"))
    t.add_row("Muted", "yes" if r.muted else "no")
    for k, v in sorted(r.meta.items()):
        if v not in ("", None, [], {}):
            t.add_row(f"  {k}", Text(", ".join(map(str, v)) if isinstance(v, list) else str(v)))
    t.add_row("Created", f"{local_time(r.created_at, app.cfg)} by {r.created_by or '-'}")
    t.add_row("Updated", local_time(r.updated_at, app.cfg))
    console.print(t)

    schedule = notification_schedule(app, r)
    if schedule:
        console.print("\n[bold]Notification schedule[/bold]")
        for when, label, state in schedule:
            console.print(f"  {when}  {label:<24} {state}")
    if history:
        console.print("\n[bold]Recent notifications[/bold]")
        for h in history:
            style = "green" if h["status"] == "sent" else "red"
            console.print(f"  {local_time(h['created_at'], app.cfg)}  stage {h['stage']:>2}d  "
                          f"[{style}]{h['status']}[/{style}]  {escape(h['channels'] or '')} "
                          f"{escape(h['error'] or '')}")


def recipient_list(cfg: Config, r: Reminder) -> list[str]:
    from expiry.checker import recipients_for
    return recipients_for(cfg, r)


def notification_schedule(app: App, r: Reminder) -> list[tuple[str, str, str]]:
    from expiry.checker import due_stage
    from expiry.notify import stage_label
    ref = app.today
    days_before = list(app.cfg.get("notify.days_before") or [])
    on_day = bool(app.cfg.get("notify.on_expiry_day", True))
    stages = sorted({d for d in days_before if d > 0} | ({0} if on_day else set()), reverse=True)
    sent = app.store.sent_stages(r.id, r.expires_on)
    current = due_stage(r.days_left(ref), days_before, on_day)
    out = []
    for s in stages:
        when = r.expires_on - timedelta(days=s)
        if s in sent:
            state = "[green]sent[/green]"
        elif any(x < s for x in sent):
            state = "[dim]skipped[/dim]"
        elif r.muted or r.status != "active":
            state = f"[dim]{'muted' if r.muted else r.status}[/dim]"
        elif s == current:
            state = "[yellow]due at next check[/yellow]"
        elif when < ref:
            state = "[dim]skipped[/dim]"
        else:
            state = "scheduled"
        out.append((app.fmt(when), stage_label(s), state))
    return out


@cli.command()
@click.argument("rid", metavar="ID", type=int)
@click.option("--name", help="New name.")
@click.option("-d", "--date", "date_str", metavar="DATE", help="New expiry date (DD/MM/YYYY, YYYY-MM-DD or +90d...).")
@click.option("-n", "--notes", help="Replace notes ('' to clear).")
@click.option("--append-note", metavar="TEXT", help="Append text to the existing notes.")
@click.option("--notify", multiple=True, metavar="EMAIL", help="Replace the extra recipients.")
@click.option("--add-notify", multiple=True, metavar="EMAIL", help="Add extra recipient(s).")
@click.option("--clear-notify", is_flag=True, help="Remove all extra recipients.")
@click.option("--mute/--unmute", default=None, help="Stop / resume notifications for this reminder.")
@pass_app
def edit(app: App, rid: int, name: str | None, date_str: str | None, notes: str | None, append_note: str | None,
         notify: tuple[str, ...], add_notify: tuple[str, ...], clear_notify: bool, mute: bool | None) -> None:
    """Edit a reminder. Without options, prompts for each field interactively.

    \b
    Examples:
      expiry edit 3 --date 30/09/2027          # renewed: notifications start over
      expiry edit 3 --notes "owner: team-x"
      expiry edit 3 --mute
      expiry edit 3                            # interactive
    """
    r = app.reminder(rid)
    ref = app.today
    changes: dict[str, Any] = {}
    no_options = not any([name, date_str, notes is not None, append_note, notify, add_notify, clear_notify,
                          mute is not None])
    if no_options:
        if not sys.stdin.isatty():
            raise click.UsageError("nothing to change; pass options like --date/--notes or run interactively")
        console.print(f"Editing [cyan]#{r.id}[/cyan] (press Enter to keep the current value)")
        name = click.prompt("Name", default=r.name)
        date_str = click.prompt("Expiry date", default=app.fmt(r.expires_on))
        notes = click.prompt("Notes", default=r.notes, show_default=bool(r.notes))
        notify = (click.prompt("Extra recipients (comma separated)", default=",".join(r.notify),
                               show_default=bool(r.notify)),)
        clear_notify = not notify[0].strip()
        mute = click.confirm("Muted", default=r.muted)

    if name:
        changes["name"] = name.strip()
    if date_str:
        changes["expires_on"] = app.parse(date_str)
    if notes is not None:
        changes["notes"] = notes
    if append_note:
        base = changes.get("notes", r.notes)
        changes["notes"] = f"{base}; {append_note}" if base else append_note
    if clear_notify:
        changes["notify"] = []
    elif notify:
        changes["notify"] = parse_emails_arg(notify)
    if add_notify:
        changes["notify"] = split_emails(changes.get("notify", r.notify) + parse_emails_arg(add_notify))
    if mute is not None:
        changes["muted"] = mute

    if r.source != "manual" and ("expires_on" in changes and changes["expires_on"] != r.expires_on
                                 or "name" in changes and changes["name"] != r.name):
        warn(f"this reminder is synced from '{r.source}': name/date will be overwritten by the next sync")
    updated = app.store.update(rid, actor(), **changes)
    if updated == r:
        console.print("Nothing changed.")
        return
    ok(f"Updated [cyan]#{updated.id}[/cyan] {escape(updated.name)} — expires {app.fmt(updated.expires_on)} "
       f"({describe_days(updated.days_left(ref))})" + (" [dim](muted)[/dim]" if updated.muted else ""))


@cli.command()
@click.argument("rids", metavar="ID...", type=int, nargs=-1, required=True)
@click.option("-y", "--yes", is_flag=True, help="Do not ask for confirmation.")
@pass_app
def rm(app: App, rids: tuple[int, ...], yes: bool) -> None:
    """Remove reminder(s).

    Manual reminders are deleted. Reminders that come from a sync (Entra, SSL) are
    marked 'ignored' instead so the next sync does not re-create them; bring them back
    with `expiry restore ID`.
    """
    reminders = [app.reminder(rid) for rid in dict.fromkeys(rids)]
    if not yes:
        console.print(reminders_table(reminders, app.today, app.cfg.date_format))
        if not click.confirm(f"Remove {len(reminders)} reminder(s)?", default=False):
            raise click.Abort()
    for r in reminders:
        result = app.store.remove(r.id, actor())
        if result == "deleted":
            ok(f"Removed #{r.id} {escape(r.name)}")
        else:
            ok(f"Ignored #{r.id} {escape(r.name)} (synced from {r.source}; `expiry restore {r.id}` to undo)")


@cli.command()
@click.argument("rid", metavar="ID", type=int)
@pass_app
def restore(app: App, rid: int) -> None:
    """Re-activate an ignored or archived reminder."""
    r = app.store.restore(app.reminder(rid).id, actor())
    ok(f"Restored #{r.id} {escape(r.name)}")


# ============================================================================ ssl


@cli.group(cls=AliasedGroup)
def ssl() -> None:
    """Track SSL/TLS certificate expiry of domains and IPs.

    \b
    The certificate is read directly from the server (no trust validation needed, so
    self-signed, internal and already-expired certificates work too). Every sync
    refreshes the date, so a renewed certificate automatically resets the reminders.
    """


@ssl.command("add")
@click.argument("targets", metavar="HOST[:PORT]...", nargs=-1, required=True)
@click.option("--sni", default="", metavar="NAME", help="Server name to request (useful when HOST is an IP).")
@click.option("--name", default="", help="Display name for the reminder (default: 'SSL host').")
@click.option("-n", "--notes", default="", help="Notes for the reminder.")
@click.option("-f", "--force", is_flag=True, help="Add even if the host cannot be reached right now.")
@pass_app
def ssl_add(app: App, targets: tuple[str, ...], sni: str, name: str, notes: str, force: bool) -> None:
    """Start tracking the certificate of one or more hosts.

    \b
    Examples:
      expiry ssl add example.com
      expiry ssl add mail.example.com:993 intranet.local:8443
      expiry ssl add 10.0.0.15 --sni portal.example.com --notes "F5 VIP"
      expiry ssl add https://app.example.com/login      # URLs are accepted
    """
    from expiry.sources.sslcert import SslSource, Target, config_targets, probe

    if not app.cfg.get("sources.ssl.enabled"):
        warn("sources.ssl.enabled is false in the config: targets are stored but not refreshed by sync")
    if len(targets) > 1 and name:
        raise click.UsageError("--name can only be used with a single host")
    src = SslSource(app.cfg, app.store)
    configured = {t.external_id for t in config_targets(app.cfg)}
    failures = 0
    for raw in targets:
        try:
            host, port = parse_host_port(raw)
        except ValueError as exc:
            raise click.BadParameter(str(exc)) from exc
        target = Target(host, port, sni, name, notes)
        if app.store.find_ssl_target(host, port, sni) or target.external_id in configured:
            warn(f"{target.label} is already tracked")
            continue
        try:
            info = probe(host, port, sni, src.timeout, verify=True)
        except Exception as exc:  # noqa: BLE001
            if not force:
                err.print(f"[red]✘[/red] {escape(target.label)}: {escape(str(exc))} (use --force to add anyway)")
                failures += 1
                continue
            info = None
            warn(f"{target.label}: {exc} — added anyway, the next sync will retry")
        app.store.add_ssl_target(host, port, sni, name, notes, actor())
        if info is None:
            continue
        item = src.item_for(target, info)
        app.store.upsert_external("ssl", item.external_id, item.name, item.expires_on, item.meta, actor(),
                                  notes=notes)
        r = app.store.get_by_external_id(item.external_id)
        trust = "" if info.trusted else f" [yellow](untrusted: {escape(info.verify_error)})[/yellow]"
        ok(f"Tracking {escape(target.label)} → reminder [cyan]#{r.id}[/cyan], expires {app.fmt(r.expires_on)} "
           f"({describe_days(r.days_left(app.today))}), issuer {escape(info.issuer)}{trust}")
    if failures:
        sys.exit(1)


@ssl.command("list")
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@pass_app
def ssl_list(app: App, as_json: bool) -> None:
    """List tracked SSL targets and their current certificate expiry."""
    from expiry.sources.sslcert import config_targets, external_id

    ref = app.today
    rows = []
    for t in app.store.ssl_targets():
        rows.append((str(t.id), t.host, t.port, t.sni, external_id(t.host, t.port, t.sni), t.notes))
    for t in config_targets(app.cfg):
        rows.append(("config", t.host, t.port, t.sni, t.external_id, t.notes))
    data = []
    for tid, host, port, sni, ext, notes in rows:
        r = app.store.get_by_external_id(ext)
        data.append({"target": tid, "host": host, "port": port, "sni": sni, "notes": notes,
                     "reminder_id": r.id if r else None, "expires_on": r.expires_on.isoformat() if r else None,
                     "days_left": r.days_left(ref) if r else None,
                     "issuer": r.meta.get("issuer") if r else None, "status": r.status if r else "not checked yet"})
    if as_json:
        print_json(data)
        return
    if not data:
        console.print("No SSL targets. Add one with: expiry ssl add example.com")
        return
    t = Table(box=box.SIMPLE_HEAD, pad_edge=False, header_style="bold")
    for col, kw in [("Target", {"style": "cyan"}), ("Host", {}), ("Port", {"justify": "right"}), ("SNI", {}),
                    ("Reminder", {"justify": "right"}), ("Expires", {}), ("Days left", {"justify": "right"}),
                    ("Issuer", {"style": "dim"})]:
        t.add_column(col, **kw)
    for d in sorted(data, key=lambda d: d["expires_on"] or "9999"):
        t.add_row(d["target"], Text(d["host"]), str(d["port"]), Text(d["sni"] or ""),
                  f"#{d['reminder_id']}" if d["reminder_id"] else "-", app.fmt(d["expires_on"]),
                  days_text(d["days_left"]) if d["days_left"] is not None else Text(d["status"], style="dim"),
                  Text(d["issuer"] or ""))
    console.print(t)
    console.print("[dim]Targets marked 'config' are defined in the config file (sources.ssl.hosts).[/dim]")


@ssl.command("rm")
@click.argument("target")
@click.option("--sni", default="", help="SNI of the target, if it was added with one.")
@pass_app
def ssl_rm(app: App, target: str, sni: str) -> None:
    """Stop tracking an SSL target (by target id from `expiry ssl list`, or HOST[:PORT])."""
    from expiry.sources.sslcert import config_targets, external_id

    if target.isdigit():
        t = app.store.get_ssl_target(int(target))
    else:
        host, port = parse_host_port(target)
        t = app.store.find_ssl_target(host, port, sni)
        if t is None and external_id(host, port, sni) in {c.external_id for c in config_targets(app.cfg)}:
            raise click.ClickException(f"{target} is defined in the config file (sources.ssl.hosts); remove it there")
    if t is None:
        raise click.ClickException(f"no SSL target '{target}' (see `expiry ssl list`)")
    app.store.remove_ssl_target(t.id, actor())
    app.store.archive_external(external_id(t.host, t.port, t.sni), actor(), "SSL target removed")
    ok(f"No longer tracking {escape(t.host)}:{t.port}" + (f" ({escape(t.sni)})" if t.sni else ""))


@ssl.command("check")
@click.argument("target", metavar="HOST[:PORT]")
@click.option("--sni", default="", help="Server name to request (useful for IPs).")
@click.option("--timeout", default=10.0, show_default=True, help="Connection timeout in seconds.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@pass_app
def ssl_check(app: App, target: str, sni: str, timeout: float, as_json: bool) -> None:
    """Inspect the certificate of a host right now (nothing is saved)."""
    from expiry.sources.sslcert import probe

    host, port = parse_host_port(target)
    try:
        info = probe(host, port, sni, timeout, verify=True)
    except Exception as exc:  # noqa: BLE001
        raise click.ClickException(f"{host}:{port}: {exc}") from exc
    days = (info.not_after.date() - datetime.now(timezone.utc).date()).days
    if as_json:
        print_json({**info.meta(), "days_left": days, "trusted": info.trusted, "verify_error": info.verify_error})
        return
    t = Table(box=None, show_header=False, pad_edge=False)
    t.add_column(style="bold", no_wrap=True)
    t.add_column(overflow="fold")
    t.add_row("Host", f"{host}:{port}" + (f" (SNI {sni})" if sni else ""))
    t.add_row("Subject", Text(info.subject))
    t.add_row("Issuer", Text(info.issuer))
    t.add_row("Valid from", info.not_before.strftime(f"{app.cfg.date_format} %H:%M UTC"))
    t.add_row("Expires", info.not_after.strftime(f"{app.cfg.date_format} %H:%M UTC"))
    t.add_row("Days left", days_text(days))
    t.add_row("Trusted", Text("yes", style="green") if info.trusted else
              Text(f"no — {info.verify_error}" if info.trusted is False else f"unknown — {info.verify_error}",
                   style="yellow"))
    t.add_row("SANs", Text(", ".join(info.san[:20]) + (f" … (+{len(info.san) - 20})" if len(info.san) > 20 else "")))
    t.add_row("Serial", info.serial)
    t.add_row("SHA-256", info.sha256)
    console.print(t)


@ssl.command("discover")
@click.argument("domain")
@click.option("--add", "do_add", is_flag=True, help="Track every reachable host that is not tracked yet.")
@click.option("-p", "--port", default=443, show_default=True, help="Port to probe.")
@click.option("--timeout", default=5.0, show_default=True, help="Per-host connection timeout.")
@click.option("--limit", default=300, show_default=True, help="Maximum number of names to probe.")
@click.option("-y", "--yes", is_flag=True, help="Do not ask before adding.")
@pass_app
def ssl_discover(app: App, domain: str, do_add: bool, port: int, timeout: float, limit: int, yes: bool) -> None:
    """Find hosts under DOMAIN via Certificate Transparency logs (crt.sh), probe
    each one and show its certificate expiry. With --add, start tracking them.

    \b
    Example:
      expiry ssl discover example.com
      expiry ssl discover example.com --add
    """
    from expiry.sources.sslcert import SslSource, Target, discover, probe

    with console.status(f"Querying certificate transparency logs for {domain} ..."):
        try:
            names = discover(domain)
        except Exception as exc:  # noqa: BLE001
            raise click.ClickException(f"crt.sh lookup failed: {exc}") from exc
    if len(names) > limit:
        warn(f"{len(names)} names found, probing the first {limit} (use --limit)")
        names = names[:limit]

    def run(n: str):
        try:
            return n, probe(n, port, "", timeout), None
        except Exception as exc:  # noqa: BLE001
            return n, None, exc

    with console.status(f"Probing {len(names)} host(s) on port {port} ..."):
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(run, names))

    ref = app.today
    src = SslSource(app.cfg, app.store)
    tracked = {t.external_id for t in src.targets()}
    t = Table(box=box.SIMPLE_HEAD, pad_edge=False, header_style="bold")
    for col in ("Host", "Expires", "Days left", "Issuer", "Tracked"):
        t.add_column(col)
    reachable = []
    for n, info, exc in sorted(results, key=lambda x: (x[1] is None, x[1].not_after if x[1] else 0, x[0])):
        target = Target(n, port)
        is_tracked = target.external_id in tracked
        if info is None:
            t.add_row(Text(n), "-", Text("unreachable", style="dim"), Text(str(exc)[:60], style="dim"), "")
            continue
        exp = info.not_after.astimezone(src.tz).date()
        t.add_row(Text(n), app.fmt(exp), days_text((exp - ref).days), Text(info.issuer),
                  "yes" if is_tracked else "")
        if not is_tracked:
            reachable.append((target, info))
    console.print(t)
    console.print(f"{len(names)} name(s), {sum(1 for r in results if r[1])} reachable, "
                  f"{len(reachable)} not tracked yet")
    if not do_add or not reachable:
        if reachable and not do_add:
            console.print("[dim]Run again with --add to track them.[/dim]")
        return
    if not yes and not click.confirm(f"Track {len(reachable)} host(s)?", default=True):
        raise click.Abort()
    for target, info in reachable:
        app.store.add_ssl_target(target.host, target.port, "", "", f"discovered from {domain}", actor())
        item = src.item_for(target, info)
        app.store.upsert_external("ssl", item.external_id, item.name, item.expires_on, item.meta, actor(),
                                  notes=f"discovered from {domain}")
    ok(f"Now tracking {len(reachable)} more host(s)")


@ssl.command("scan")
@click.option("-d", "--domain", "domains", multiple=True, metavar="DOMAIN",
              help="Keep certificates issued for this domain (repeatable). Default: sources.ssl.scan.domains.")
@click.option("-n", "--name", "names", multiple=True, metavar="NAME",
              help="Extra host name to try besides the built-in list (repeatable), e.g. erp or erp.example.com.")
@click.option("--names-file", metavar="FILE",
              help="More host names from a file: one per line, or a DNS zone export (Windows CSV / BIND). "
                   "Use - to read from stdin: expiry ssl scan -d example.com --names-file - -y < names.txt")
@click.option("--network", "networks", multiple=True, metavar="CIDR",
              help="Also scan every address in this range (repeatable), e.g. 10.1.2.0/24.")
@click.option("-p", "--ports", default=None, metavar="LIST",
              help="Ports to check, e.g. 443,8443,993 (default: sources.ssl.scan.ports = 443,8443,9443).")
@click.option("--no-logs", is_flag=True, help="Don't look up public certificate logs (crt.sh).")
@click.option("--wildcards", "wildcards_only", is_flag=True, help="Only show wildcard certificates.")
@click.option("--timeout", default=None, type=float, help="Per-connection timeout in seconds (default 3).")
@click.option("--add", "do_add", is_flag=True, help="Track every location found that isn't tracked yet.")
@click.option("-y", "--yes", is_flag=True, help="Do not ask before adding.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@pass_app
def ssl_scan(app: App, domains: tuple[str, ...], names: tuple[str, ...], names_file: str | None,
             networks: tuple[str, ...], ports: str | None, no_logs: bool, wildcards_only: bool, timeout: float | None, do_add: bool,
             yes: bool, as_json: bool) -> None:
    """Find where your certificates are installed, including wildcards, and optionally track them.

    \b
    Tries typical server names under each domain (www, mail, vpn, wiki, portal, ... plus
    your --name values) using this server's DNS, so internal names work when run on your
    network; optionally scans address ranges (--network) for servers you reach only by IP;
    and looks up public names in certificate logs. Only certificates issued for your
    domains are kept, grouped by certificate, so you see every server a wildcard is on.
    \b
    Examples:
      expiry ssl scan --domain example.com
      expiry ssl scan --domain example.com --names-file - < dns-export.csv
      expiry ssl scan --domain example.com --network 10.1.2.0/24 --ports 443,8443
      expiry ssl scan --domain example.com --wildcards --add
    \b
    Network scans connect to every address: tell your network/security team first.
    Run it on a schedule with sources.ssl.scan in config.yaml.
    """
    from zoneinfo import ZoneInfo

    from expiry.sources import sslscan
    from expiry.sources.sslcert import SslSource

    opts = app.cfg.get("sources.ssl.scan") or {}
    domains_l = list(domains) or list(opts.get("domains") or [])
    if not domains_l:
        raise click.UsageError("give --domain example.com (or set sources.ssl.scan.domains)")
    names_l = list(names) or list(opts.get("names") or [])
    file_names = names_file or (opts.get("names_file") if not names else None)
    if file_names == "-":
        if do_add and not yes:
            raise click.UsageError("with --names-file - also pass -y (stdin is used for the names)")
        from_file = sslscan.parse_names(sys.stdin.read())
        console.print(f"[dim]{len(from_file)} name(s) read from stdin[/dim]")
        names_l += from_file
    elif file_names:
        if not Path(file_names).is_file():
            raise click.BadParameter(f"{file_names} not found. The command runs inside the container: put the "
                                     "file in /etc/expiry/ (seen as /config/ inside), or pipe it: --names-file - < file")
        from_file = sslscan.read_names_file(file_names)
        names_l += from_file
        console.print(f"[dim]{len(from_file)} name(s) read from {file_names}[/dim]")
    networks_l = list(networks) or ([] if domains else list(opts.get("networks") or []))
    try:
        ports_l = [int(p) for p in ports.split(",")] if ports else list(opts.get("ports") or sslscan.DEFAULT_PORTS)
    except ValueError as exc:
        raise click.BadParameter("ports must look like 443,8443") from exc
    use_logs = not no_logs and bool(opts.get("certificate_logs", True))
    what = f"{', '.join(domains_l)}" + (f" + {', '.join(networks_l)}" if networks_l else "")
    try:
        with console.status(f"Scanning {what} on port(s) {', '.join(map(str, ports_l))} ..."):
            result = sslscan.scan(domains_l, names_l, networks_l, ports_l, use_logs,
                                  timeout or float(opts.get("timeout") or 3))
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    ids, addresses = sslscan.tracked_state(SslSource(app.cfg, app.store).targets())
    app.store.audit(actor(), "scan", None, f"{what}, ports {','.join(map(str, ports_l))}: checked "
                     f"{result.names_checked} names, {result.addresses_checked} addresses, "
                     f"{len(result.found)} locations found")
    groups = result.by_certificate()
    if wildcards_only:
        groups = {k: v for k, v in groups.items() if sslscan.is_wildcard(v[0].info)}
    ref = app.today

    if as_json:
        print_json([{
            "certificate": v[0].info.common_name, "wildcard": sslscan.is_wildcard(v[0].info),
            "issuer": v[0].info.issuer, "expires_on": v[0].info.not_after.date().isoformat(),
            "sha256": k, "san": v[0].info.san,
            "locations": [{"host": f.host, "port": f.port, "sni": f.sni, "address": f.address, "via": f.via,
                           "tracked": sslscan.is_tracked(f, ids, addresses)} for f in v],
        } for k, v in groups.items()])
        return

    for w in result.warnings:
        warn(w)
    console.print(f"Checked {result.names_checked} name(s)"
                  + (f" and {result.addresses_checked} address(es)" if result.addresses_checked else "")
                  + f": {sum(len(v) for v in groups.values())} location(s) of {len(groups)} certificate(s).")
    if not groups:
        return
    t = Table(box=box.SIMPLE_HEAD, pad_edge=False, header_style="bold")
    for col, kw in [("Certificate", {}), ("Issuer", {"style": "dim"}), ("Expires", {}),
                    ("Days left", {"justify": "right"}), ("Location", {}), ("Found via", {"style": "dim"}),
                    ("Tracked", {})]:
        t.add_column(col, overflow="fold", **kw)
    new: list = []
    for i, (sha, locs) in enumerate(groups.items()):
        info = locs[0].info
        exp = info.not_after.astimezone(ZoneInfo(app.cfg.timezone)).date()
        for j, f in enumerate(locs):
            tracked = sslscan.is_tracked(f, ids, addresses)
            if not tracked:
                new.append(f)
            cert = Text(info.common_name or "-") + (Text(" wildcard", style="magenta") if sslscan.is_wildcard(info) else "")
            t.add_row(cert if j == 0 else "", Text(info.issuer) if j == 0 else "", app.fmt(exp) if j == 0 else "",
                      days_text((exp - ref).days) if j == 0 else "", Text(f.location),
                      f.via + (f" {f.address}" if f.address != f.host else ""),
                      Text("yes", style="green") if tracked else Text("new", style="yellow"),
                      end_section=j == len(locs) - 1 and i < len(groups) - 1)
    console.print(t)
    if not new:
        ok("Everything found is already tracked")
        return
    if not do_add:
        console.print(f"[dim]{len(new)} new location(s). Run again with --add to track them.[/dim]")
        return
    if not yes and not click.confirm(f"Track {len(new)} new location(s)?", default=True):
        raise click.Abort()
    added = sslscan.track(app.store, new, actor(), ZoneInfo(app.cfg.timezone), ids, addresses)
    ok(f"Now tracking {len(added)} more location(s)")


# ============================================================================ sync / check


@cli.command()
@click.option("-s", "--source", type=click.Choice(["entra", "ssl"]), help="Only sync this source.")
@click.option("--dry-run", is_flag=True, help="Show what would be imported without saving.")
@pass_app
def sync(app: App, source: str | None, dry_run: bool) -> None:
    """Pull expiry dates from the enabled sources (Entra ID, SSL) now.

    New credentials/certificates become reminders, changed dates are updated
    (renewals), and items that disappeared from the source are archived. The
    daemon runs this automatically (schedule.sync).
    """
    from expiry.sources import build_sources, run_sync

    if not build_sources(app.cfg, app.store, source):
        raise click.ClickException("no source enabled (set sources.entra.enabled / sources.ssl.enabled in the config)")
    with console.status("Syncing ..."):
        results = run_sync(app.cfg, app.store, source, dry_run)
    ref = app.today
    for r in results:
        if r.failed:
            err.print(f"[red]✘ {r.source}: sync failed[/red]")
        elif dry_run:
            console.print(f"[bold]{r.source}[/bold]: {r.found} item(s) found (dry run, nothing saved)")
            t = Table(box=box.SIMPLE_HEAD, pad_edge=False)
            for col in ("Name", "Expires", "Days left"):
                t.add_column(col)
            for it in sorted(r.items, key=lambda i: i.expires_on):
                t.add_row(Text(it.name), app.fmt(it.expires_on), days_text((it.expires_on - ref).days))
            if r.items:
                console.print(t)
        else:
            ok(f"{r.source}: found {r.found} · new {r.created} · updated {r.updated} · unchanged {r.unchanged}"
               f" · archived {r.archived}" + (f" · ignored {r.ignored}" if r.ignored else ""))
        for e in r.errors:
            err.print(f"  [yellow]{escape(e)}[/yellow]")
    if any(r.failed for r in results):
        sys.exit(1)


@cli.command()
@click.option("--dry-run", is_flag=True, help="Show what would be sent without sending.")
@pass_app
def check(app: App, dry_run: bool) -> None:
    """Evaluate reminders and send the notifications that are due now.

    Safe to run any time: each stage (30/14/1 days, expiry day) is only sent once
    per reminder and expiry date. The daemon runs this automatically (schedule.check).
    """
    from expiry.checker import run_check
    from expiry.notify import stage_label

    ref = app.today
    result = run_check(app.cfg, app.store, ref, dry_run=dry_run)
    if not result.due:
        console.print("Nothing is due. ✔")
        return
    t = Table(box=box.SIMPLE_HEAD, pad_edge=False, header_style="bold")
    for col in ("ID", "Name", "Expires", "Days left", "Stage", "Recipients"):
        t.add_column(col)
    for d in result.due:
        t.add_row(str(d.reminder.id), Text(d.reminder.name), app.fmt(d.reminder.expires_on),
                  days_text(d.reminder.days_left(ref)), stage_label(d.stage), Text(", ".join(d.recipients) or "-"))
    console.print(t)
    if dry_run:
        console.print(f"{len(result.due)} notification(s) would be sent (dry run).")
        return
    if result.sent:
        ok(f"{result.sent} notification(s) sent")
    if result.failed:
        err.print(f"[red]✘ {result.failed} failed[/red] (will retry at the next check)")
    for e in result.errors:
        err.print(f"  [yellow]{escape(e)}[/yellow]")
    if result.failed:
        sys.exit(1)


@cli.command("test-notify")
@click.option("--to", multiple=True, metavar="EMAIL", help="Send the test email here instead of notify.emails.")
@click.option("--email/--no-email", default=True, help="Test the email channel.")
@click.option("--webhooks/--no-webhooks", default=True, help="Test the webhook channel(s).")
@pass_app
def test_notify(app: App, to: tuple[str, ...], email: bool, webhooks: bool) -> None:
    """Send a test notification with a sample reminder (nothing is saved)."""
    from expiry.notify import EmailSender, Renderer, item_context, send_webhook

    ref = app.today
    sample = Reminder(id=0, name="Example service (test notification)", expires_on=ref + timedelta(days=14),
                      notes="This is a test sent by `expiry test-notify`.", source="manual")
    ctx = [item_context(sample, ref, 14, app.cfg.date_format)]
    failures = 0
    if email:
        if not app.cfg.get("email.enabled"):
            warn("email is disabled in the config (email.enabled)")
        else:
            recipients = parse_emails_arg(to) if to else split_emails(app.cfg.get("notify.emails") or [])
            if not recipients:
                raise click.ClickException("no recipients: use --to EMAIL or set notify.emails")
            try:
                EmailSender(app.cfg).send(recipients, Renderer(app.cfg).render(ctx, ref))
                ok(f"Test email sent to {', '.join(recipients)} via {app.cfg.get('email.transport')}")
            except Exception as exc:  # noqa: BLE001
                err.print(f"[red]✘ email failed:[/red] {escape(str(exc))}")
                failures += 1
    if webhooks:
        for hook in app.cfg.get("notify.webhooks") or []:
            try:
                send_webhook(hook, ctx)
                ok(f"Test webhook sent ({hook.get('format', 'generic')})")
            except Exception as exc:  # noqa: BLE001
                err.print(f"[red]✘ webhook ({hook.get('format', 'generic')}) failed:[/red] {escape(str(exc))}")
                failures += 1
    if failures:
        sys.exit(1)


# ============================================================================ status / history / audit


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@pass_app
def status(app: App, as_json: bool) -> None:
    """Show service status: daemon heartbeat, last/next sync and check, counts."""
    cfg, store, ref = app.cfg, app.store, app.today
    daemon = store.kv_get("daemon", {})
    last_sync = store.kv_get("last_sync", {})
    last_check = store.kv_get("last_check", {})
    from expiry import health
    active = store.list()
    errors, warnings = validate(cfg)
    alive = _daemon_alive(daemon)
    last_backup = store.kv_get("last_backup", {})
    problems = health.problems(store, cfg)
    data = {
        "version": __version__, "config": str(cfg.path) if cfg.path else None, "database": cfg.db_path,
        "timezone": cfg.timezone, "today": ref.isoformat(), "daemon": daemon, "daemon_running": alive,
        "last_sync": last_sync, "last_check": last_check, "last_backup": last_backup, "health_problems": problems,
        "counts": {"active": len(active), "expired": sum(1 for r in active if r.days_left(ref) < 0),
                   "within_30_days": sum(1 for r in active if 0 <= r.days_left(ref) <= 30)},
        "config_errors": errors, "config_warnings": warnings,
    }
    if as_json:
        print_json(data)
        return
    tz = cfg.timezone
    t = Table(box=None, show_header=False, pad_edge=False)
    t.add_column(style="bold", no_wrap=True)
    t.add_column(overflow="fold")
    t.add_row("Version", __version__)
    t.add_row("Config", str(cfg.path) if cfg.path else "[yellow]none found, using defaults[/yellow]")
    t.add_row("Database", cfg.db_path)
    t.add_row("Timezone", f"{tz} (today is {app.fmt(ref)}, date format {cfg.date_format})")
    t.add_row("Daemon", ("[green]running[/green]" if alive else "[red]not running[/red]") +
              (f" (since {local_time(daemon.get('started'), cfg)}, heartbeat {local_time(daemon.get('heartbeat'), cfg)})"
               if daemon else ""))
    nxt = daemon.get("next", {}) if daemon else {}
    t.add_row("Schedule", f"sync '{cfg.get('schedule.sync')}' (next {local_time(nxt.get('sync'), cfg)}), "
                          f"check '{cfg.get('schedule.check')}' (next {local_time(nxt.get('check'), cfg)})")
    if problems:
        t.add_row("Health", "[red]" + "; ".join(
            f"{health.label(c)} failing since {local_time(s.get('since'), cfg)} ({s.get('failures')}x)"
            for c, s in problems.items()) + "[/red]")
    else:
        t.add_row("Health", "[green]ok[/green]" + ("" if cfg.get("alerts.enabled") else " (alerts disabled)"))
    sources = [s for s in ("entra", "ssl") if cfg.get(f"sources.{s}.enabled")]
    t.add_row("Sources", ", ".join(sources) or "none (manual reminders only)")
    if cfg.get("entra.certificate_path"):
        from expiry.certauth import CertError, load_credential
        try:
            c = load_credential(cfg.get("entra.certificate_path"), cfg.get("entra.certificate_thumbprint") or "")
            auth = "certificate" + (f" (expires {app.fmt(c.not_after.date())})" if c.not_after else "")
        except CertError as exc:
            auth = f"[red]certificate problem: {escape(str(exc))}[/red]"
        t.add_row("Entra login", auth)
    elif cfg.get("entra.client_secret"):
        t.add_row("Entra login", "client secret [dim](a certificate is more secure: expiry entra cert-create)[/dim]")
    if cfg.get("sources.ssl.enabled") and cfg.get("sources.ssl.scan.enabled"):
        ls = store.kv_get("last_scan", {})
        t.add_row("Scan", f"{', '.join(cfg.get('sources.ssl.scan.domains') or [])}"
                          + (f" + {', '.join(cfg.get('sources.ssl.scan.networks'))}"
                             if cfg.get("sources.ssl.scan.networks") else "")
                          + f", '{cfg.get('sources.ssl.scan.schedule')}' (next {local_time(nxt.get('scan'), cfg)}), "
                          + (f"last {local_time(ls.get('at'), cfg)}: {ls.get('found')} found, {ls.get('added')} added"
                             if ls else "not run yet"))
    if cfg.get("backup.enabled"):
        lb = (f"last {local_time(last_backup.get('at'), cfg)}" if last_backup else "none yet")
        t.add_row("Backups", f"{cfg.backup_dir}, keep {cfg.get('backup.keep')}, "
                             f"'{cfg.get('backup.schedule')}' (next {local_time(nxt.get('backup'), cfg)}), {lb}")
    else:
        t.add_row("Backups", "[yellow]disabled[/yellow]")
    channels = []
    if cfg.get("email.enabled"):
        channels.append(f"email via {cfg.get('email.transport')} → {', '.join(cfg.get('notify.emails') or []) or '-'}")
    channels += [f"webhook ({w.get('format', 'generic')})" for w in cfg.get("notify.webhooks") or []]
    t.add_row("Notify", "; ".join(channels) or "[yellow]no channel[/yellow]")
    t.add_row("Stages", ", ".join(f"{d}d" for d in cfg.get("notify.days_before") or []) +
              (" + expiry day" if cfg.get("notify.on_expiry_day") else "") + f" ({cfg.get('notify.mode')})")
    if last_sync:
        parts = []
        for name, s in last_sync.get("results", {}).items():
            parts.append(f"{name}: " + ("[red]failed[/red]" if s["failed"] else
                                        f"{s['found']} found, {s['created']} new, {s['archived']} archived") +
                         (f" [yellow]({len(s['errors'])} error(s))[/yellow]" if s["errors"] else ""))
        t.add_row("Last sync", f"{local_time(last_sync.get('at'), cfg)} — " + ("; ".join(parts) or "no sources"))
    else:
        t.add_row("Last sync", "never")
    if last_check:
        c = last_check.get("result", {})
        t.add_row("Last check", f"{local_time(last_check.get('at'), cfg)} — due {c.get('due', 0)}, "
                                f"sent {c.get('sent', 0)}, failed {c.get('failed', 0)}")
    else:
        t.add_row("Last check", "never")
    t.add_row("Reminders", f"{data['counts']['active']} active, {data['counts']['within_30_days']} within 30 days, "
                           f"{data['counts']['expired']} expired")
    console.print(t)
    for e in errors:
        err.print(f"[red]config error:[/red] {escape(e)}")
    for w in warnings:
        err.print(f"[yellow]config warning:[/yellow] {escape(w)}")
    for name, s in (last_sync.get("results", {}) if last_sync else {}).items():
        for e in s["errors"][:10]:
            err.print(f"[yellow]{name}:[/yellow] {escape(e)}")
    for c, s in problems.items():
        err.print(f"[red]{health.label(c)}:[/red] {escape(str(s.get('last_error')))}")


def _daemon_alive(daemon: dict) -> bool:
    from expiry.scheduler import HEARTBEAT_SECONDS
    hb = daemon.get("heartbeat") if daemon else None
    if not hb:
        return False
    age = (datetime.now(timezone.utc) - datetime.fromisoformat(hb)).total_seconds()
    return age < HEARTBEAT_SECONDS * 3


@cli.command()
@click.option("-i", "--id", "rid", type=int, help="Only notifications of this reminder.")
@click.option("-n", "--limit", default=30, show_default=True, help="Number of entries.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@pass_app
def history(app: App, rid: int | None, limit: int, as_json: bool) -> None:
    """Show notifications that were sent (or failed)."""
    rows = app.store.history(limit, rid)
    if as_json:
        print_json([dict(r) for r in rows])
        return
    if not rows:
        console.print("No notifications yet.")
        return
    t = Table(box=box.SIMPLE_HEAD, pad_edge=False, header_style="bold")
    for col in ("When", "ID", "Reminder", "Expires", "Stage", "Status", "Channels", "Recipients / error"):
        t.add_column(col, overflow="fold")
    for r in rows:
        style = "green" if r["status"] == "sent" else "red"
        t.add_row(local_time(r["created_at"], app.cfg), str(r["reminder_id"] or "-"),
                  Text(r["reminder_name"]), app.fmt(r["expires_on"]), f"{r['stage']}d", Text(r["status"], style=style),
                  r["channels"] or "-", Text(r["error"] if r["status"] != "sent" else r["recipients"]))
    console.print(t)


@cli.command()
@click.option("-i", "--id", "rid", type=int, help="Only changes to this reminder.")
@click.option("-n", "--limit", default=30, show_default=True, help="Number of entries.")
@click.option("--json", "as_json", is_flag=True, help="Output JSON.")
@pass_app
def audit(app: App, rid: int | None, limit: int, as_json: bool) -> None:
    """Show the change log: who added, edited or removed what, and sync changes."""
    rows = app.store.audit_log(limit, rid)
    if as_json:
        print_json([dict(r) for r in rows])
        return
    if not rows:
        console.print("No changes recorded yet.")
        return
    t = Table(box=box.SIMPLE_HEAD, pad_edge=False, header_style="bold")
    for col in ("When", "Actor", "Action", "ID", "Details"):
        t.add_column(col, overflow="fold")
    for r in rows:
        t.add_row(local_time(r["ts"], app.cfg), Text(r["actor"]), r["action"],
                  str(r["reminder_id"] or "-"), Text(r["details"]))
    console.print(t)


# ============================================================================ backups


@cli.group("backup", cls=AliasedGroup)
def backup_group() -> None:
    """Database backups: create, list and restore.

    \b
    The daemon backs up automatically (backup.schedule, default daily 02:30) and keeps the
    newest backup.keep files. Backups are consistent snapshots taken while the service runs.
    They go to /backups when a host folder is mounted there (recommended, e.g.
    -v /var/backups/expiry:/backups), otherwise to /data/backups inside the data volume.
    """


@backup_group.command("create")
@click.option("-d", "--dir", "directory", metavar="DIR", help="Write here instead of the backup folder.")
@pass_app
def backup_create(app: App, directory: str | None) -> None:
    """Back up the database now."""
    from expiry import backup, health
    target_dir = directory or app.cfg.backup_dir
    try:
        path = backup.create_backup(app.cfg.db_path, target_dir,
                                    keep=0 if directory else int(app.cfg.get("backup.keep") or 0))
    except Exception as exc:  # noqa: BLE001
        health.record(app.store, "backup", False, str(exc))
        raise click.ClickException(f"backup failed: {exc}") from exc
    app.store.kv_set("last_backup", {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                     "file": str(path), "size": path.stat().st_size})
    health.record(app.store, "backup", True)
    ok(f"Backup written: {path} ({path.stat().st_size // 1024 or 1} KB, "
       f"{backup.verify(path)} reminder(s))")


@backup_group.command("list")
@click.option("-d", "--dir", "directory", metavar="DIR", help="List this folder instead of the backup folder.")
@pass_app
def backup_list(app: App, directory: str | None) -> None:
    """List backups, newest first."""
    from expiry import backup
    d = directory or app.cfg.backup_dir
    items = backup.list_backups(d)
    if not items:
        console.print(f"No backups in {d}. Create one with: expiry backup create")
        return
    t = Table(box=box.SIMPLE_HEAD, pad_edge=False, header_style="bold")
    for col in ("File", "Created", "Size"):
        t.add_column(col)
    for b in items:
        kind = " [dim](before restore)[/dim]" if b.path.name.startswith(backup.PRE_RESTORE_PREFIX) else ""
        t.add_row(b.path.name + kind, local_time(b.created.isoformat(), app.cfg), f"{b.size // 1024 or 1} KB")
    console.print(t)
    console.print(f"[dim]{d}[/dim]")


@backup_group.command("restore")
@click.argument("file")
@click.option("-y", "--yes", is_flag=True, help="Do not ask for confirmation.")
@pass_app
def backup_restore(app: App, file: str, yes: bool) -> None:
    """Replace the current data with a backup (FILE name from `expiry backup list`, or a path).

    A safety copy of the current database is saved first, so a restore can be undone by
    restoring that copy.
    """
    from expiry import backup
    d = app.cfg.backup_dir
    try:
        path = backup.resolve(file, d)
        count = backup.verify(path)
    except (FileNotFoundError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    console.print(f"Backup {path.name}: {count} reminder(s). Current database: {len(app.store.list(None))}.")
    if not yes and not click.confirm("Replace the current data with this backup?", default=False):
        raise click.Abort()
    app.close()  # release our own connection before overwriting
    safety = backup.restore(path, app.cfg.db_path, d)
    with Store(app.cfg.db_path) as store:
        store.audit(actor(), "backup-restore", None, f"restored {path.name} (safety copy {safety.name})")
    ok(f"Restored {path.name}. Previous data saved as {safety.name}")


# ============================================================================ entra certificate login


@cli.group("entra", cls=AliasedGroup)
def entra_group() -> None:
    """Entra ID helpers: certificate login for the app registration.

    \b
    A certificate is more secure than a client secret: only the public certificate is uploaded
    to Entra, the private key never leaves this server.
      1. expiry entra cert-create             (creates /data/entra-auth.pem + .crt)
      2. upload the .crt to the app registration (Certificates & secrets > Certificates)
      3. config.yaml: entra.certificate_path: /data/entra-auth.pem (remove client_secret)
      4. expiry config check --connect
    """


def _cert_default_path(app: App) -> str:
    from expiry.certauth import DEFAULT_PATH
    return app.cfg.get("entra.certificate_path") or DEFAULT_PATH


@entra_group.command("cert-create")
@click.option("--path", "path", metavar="FILE", help="Where to write the key + certificate "
              "(default: entra.certificate_path or /data/entra-auth.pem).")
@click.option("--days", default=730, show_default=True, help="Validity in days.")
@click.option("--name", "common_name", default="expiry-monitor", show_default=True, help="Certificate name (CN).")
@click.option("-f", "--force", is_flag=True, help="Overwrite an existing file.")
@pass_app
def entra_cert_create(app: App, path: str | None, days: int, common_name: str, force: bool) -> None:
    """Create a key + self-signed certificate for the Entra app registration."""
    from expiry.certauth import create, public_path
    target = path or _cert_default_path(app)
    if Path(target).exists() and not force:
        raise click.ClickException(f"{target} already exists (use --force to replace it)")
    cred = create(target, days=days, common_name=common_name)
    crt = public_path(target)
    ok(f"Created {target} (private key + certificate, readable by the service only)")
    console.print(f"  Public certificate: {crt}")
    console.print(f"  Thumbprint (SHA-1): {cred.sha1_thumbprint}")
    console.print(f"  Expires:            {app.fmt(cred.not_after.date())} (tracked automatically once uploaded)")
    console.print(
        "\nNext steps:\n"
        f"  1. Copy the public certificate to your PC:  docker cp expiry:{crt} .\n"
        "     (or print it with: expiry entra cert-show --pem)\n"
        "  2. Entra admin center > App registrations > your app > Certificates & secrets >\n"
        "     Certificates > Upload certificate  (or: az ad app credential reset --id <client-id>\n"
        f"     --cert @{crt.name} --append)\n"
        f"  3. config.yaml:  entra.certificate_path: {target}   and remove entra.client_secret\n"
        "  4. expiry config check --connect   then delete the old client secret in Entra")


@entra_group.command("cert-show")
@click.option("--path", "path", metavar="FILE", help="Key + certificate file (default: entra.certificate_path).")
@click.option("--pem", is_flag=True, help="Also print the public certificate (to paste into a .crt file).")
@pass_app
def entra_cert_show(app: App, path: str | None, pem: bool) -> None:
    """Show the login certificate: thumbprint, expiry and (with --pem) the public certificate."""
    from expiry.certauth import CertError, load_credential
    target = path or _cert_default_path(app)
    try:
        cred = load_credential(target, app.cfg.get("entra.certificate_thumbprint") or "")
    except CertError as exc:
        raise click.ClickException(str(exc)) from exc
    console.print(f"File:        {target}")
    console.print(f"Subject:     {cred.subject or '-'}")
    console.print(f"Thumbprint:  {cred.sha1_thumbprint}")
    if cred.not_after:
        left = (cred.not_after.date() - app.today).days
        console.print(f"Expires:     {app.fmt(cred.not_after.date())} ({describe_days(left)})",
                      style="red" if left <= 30 else None)
    console.print(f"In use:      {'yes' if app.cfg.get('entra.certificate_path') == target else 'no (set entra.certificate_path)'}")
    if pem and cred.certificate_pem:
        click.echo("\n" + cred.certificate_pem.strip())


# ============================================================================ export / import


@cli.command()
@click.option("-f", "--format", "fmt", type=click.Choice(["json", "csv"]), default="json", show_default=True)
@click.option("-a", "--all", "show_all", is_flag=True, help="Include archived and ignored reminders.")
@click.option("-o", "--output", type=click.File("w", encoding="utf-8"), default="-", help="File (default stdout).")
@pass_app
def export(app: App, fmt: str, show_all: bool, output) -> None:
    """Export reminders as JSON or CSV, for example `expiry export > backup.json`."""
    ref = app.today
    items = [r.to_dict(ref) for r in app.store.list(statuses=None if show_all else ("active",))]
    if fmt == "json":
        output.write(json.dumps(items, indent=2, default=str) + "\n")
        return
    fields = ["id", "name", "expires_on", "days_left", "notes", "source", "status", "muted", "notify", "external_id"]
    w = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for it in items:
        w.writerow({**it, "notify": ",".join(it["notify"])})


@cli.command("import")
@click.argument("file", type=click.File("r", encoding="utf-8-sig"))
@click.option("--dry-run", is_flag=True, help="Validate and show what would be imported.")
@pass_app
def import_cmd(app: App, file, dry_run: bool) -> None:
    """Import manual reminders from a JSON or CSV file ('-' for stdin).

    \b
    CSV needs a header row with at least: name,expires_on  (optional: notes,notify,muted)
    JSON is a list of objects with the same keys (the output of `expiry export` works).
    Rows whose name + date already exist are skipped. Synced (entra/ssl) rows are skipped.
    """
    text = file.read()
    try:
        rows = json.loads(text) if text.lstrip().startswith(("[", "{")) else list(csv.DictReader(io.StringIO(text)))
    except (ValueError, csv.Error) as exc:
        raise click.ClickException(f"cannot parse input: {exc}") from exc
    if isinstance(rows, dict):
        rows = [rows]
    ref = app.today
    existing = {(r.name.lower(), r.expires_on) for r in app.store.list(statuses=None)}
    added = skipped = 0
    for n, row in enumerate(rows, 1):
        if (row.get("source") or "manual") != "manual":
            skipped += 1
            continue
        name = (row.get("name") or "").strip()
        try:
            expires = parse_date(str(row.get("expires_on") or row.get("date") or ""), ref)
        except ValueError as exc:
            raise click.ClickException(f"row {n}: {exc}") from exc
        if not name:
            raise click.ClickException(f"row {n}: name is required")
        if (name.lower(), expires) in existing:
            skipped += 1
            continue
        notify = row.get("notify") or []
        emails = split_emails(notify if isinstance(notify, list) else str(notify))
        muted = str(row.get("muted", "")).lower() in ("1", "true", "yes")
        if not dry_run:
            r = app.store.add(name, expires, actor(), notes=row.get("notes") or "", notify=emails)
            if muted:
                app.store.update(r.id, actor(), muted=True)
        existing.add((name.lower(), expires))
        added += 1
    ok(f"{'Would import' if dry_run else 'Imported'} {added} reminder(s), skipped {skipped}")


# ============================================================================ config


@cli.group("config")
def config_group() -> None:
    """Show or validate the configuration."""


@config_group.command("show")
@pass_app
def config_show(app: App) -> None:
    """Print the effective configuration (defaults + file + ${ENV} values), secrets masked."""
    console.print(f"[dim]# file: {app.cfg.path or 'none (defaults only)'}[/dim]")
    click.echo(yaml.safe_dump(masked(app.cfg.data), sort_keys=False, allow_unicode=True))


@config_group.command("check")
@click.option("--connect", is_flag=True, help="Also test the Entra ID login and Graph permissions.")
@pass_app
def config_check(app: App, connect: bool) -> None:
    """Validate the configuration file (and optionally the Entra connection)."""
    errors, warnings = validate(app.cfg)
    console.print(f"Config: {app.cfg.path or 'none found (defaults)'}")
    for w in warnings:
        warn(w)
    for e in errors:
        err.print(f"[red]✘[/red] {escape(e)}")
    if connect:
        from expiry.graph import GraphClient, GraphError
        try:
            g = GraphClient(app.cfg)
            g.token()
            ok("Entra ID: authenticated (client credentials)")
            apps = g.request("GET", "/applications", params={"$top": "1", "$select": "id"}).json()
            ok(f"Graph: can read app registrations (Application.Read.All) — sample size {len(apps.get('value', []))}")
            if app.cfg.get("email.transport") == "graph":
                console.print("[dim]  Mail.Send is only verified by `expiry test-notify`.[/dim]")
        except (GraphError, OSError) as exc:
            err.print(f"[red]✘ Entra/Graph:[/red] {escape(str(exc))}")
            errors.append(str(exc))
    if errors:
        sys.exit(1)
    ok("Configuration is valid")


# ============================================================================ daemon / health / install


@cli.command()
@pass_app
def daemon(app: App) -> None:
    """Run the scheduler in the foreground (the container's default command)."""
    from expiry.scheduler import run_daemon
    run_daemon(app.config_path)


@cli.command()
@pass_app
def health(app: App) -> None:
    """Exit 0 if the daemon heartbeat is recent (used by the Docker HEALTHCHECK)."""
    alive = _daemon_alive(app.store.kv_get("daemon", {}))
    click.echo("healthy" if alive else "unhealthy: no recent daemon heartbeat")
    sys.exit(0 if alive else 1)


@cli.command()
@click.option("--target", default="/host", show_default=True, type=click.Path(file_okay=False),
              help="Where the host directories are mounted.")
@click.option("--force", is_flag=True, help="Overwrite existing config.yaml / expiry.env.")
def install(target: str, force: bool) -> None:
    """Install host files: the `expiry` wrapper command, the man page and a starter config.

    Run through Docker as root with the host directories mounted:

    \b
      docker run --rm -u 0 \\
        -v /usr/local/bin:/host/bin \\
        -v /usr/local/share/man/man1:/host/man \\
        -v /etc/expiry:/host/config \\
        ghcr.io/devlossantos/expiry:latest install
    """
    share = Path(os.environ.get("EXPIRY_SHARE_DIR", "/opt/expiry/share"))
    root = Path(target)
    done = []

    def put(src: Path, dst: Path, mode: int, overwrite: bool = True) -> None:
        if dst.exists() and not overwrite:
            console.print(f"  [dim]kept existing {dst}[/dim]")
            return
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        os.chmod(dst, mode)
        done.append(dst)
        console.print(f"  wrote {dst}")

    if not share.is_dir():
        raise click.ClickException(f"{share} not found (run this inside the expiry image)")
    if (root / "bin").is_dir():
        put(share / "expiry-host.sh", root / "bin" / "expiry", 0o755)
    if (root / "man").is_dir():
        put(share / "expiry.1", root / "man" / "expiry.1", 0o644)
    if (root / "config").is_dir():
        cfg_dir = root / "config"
        put(share / "config.example.yaml", cfg_dir / "config.example.yaml", 0o644)
        put(share / "config.example.yaml", cfg_dir / "config.yaml", 0o644, overwrite=force)
        put(share / "expiry.env.example", cfg_dir / "expiry.env", 0o600, overwrite=force)
        put(share / "templates" / "reminder.html.j2", cfg_dir / "templates" / "reminder.html.j2", 0o644,
            overwrite=force)
    if not done and not any((root / d).is_dir() for d in ("bin", "man", "config")):
        raise click.ClickException(f"nothing mounted under {root}; see `expiry install --help`")
    console.print("\nNext steps:\n"
                  "  1. Edit /etc/expiry/config.yaml and /etc/expiry/expiry.env\n"
                  "  2. Create the backup folder and start the service:\n"
                  "       sudo install -d -o 10001 -g 10001 -m 750 /var/backups/expiry\n"
                  "       sudo docker run -d --name expiry --restart unless-stopped \\\n"
                  "         --log-opt max-size=10m --log-opt max-file=5 \\\n"
                  "         --env-file /etc/expiry/expiry.env \\\n"
                  "         -v /etc/expiry:/config:ro -v expiry-data:/data \\\n"
                  "         -v /var/backups/expiry:/backups ghcr.io/devlossantos/expiry:latest\n"
                  "  3. expiry config check --connect && expiry sync && expiry list\n"
                  "  4. man expiry")


def main() -> None:
    try:
        cli(prog_name="expiry")
    except BrokenPipeError:  # e.g. `expiry list | head`
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)


if __name__ == "__main__":
    main()
