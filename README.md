# expiry

Tracks things that expire (Entra ID app secrets and certificates, SSL/TLS certificates, licenses,
domains, tokens) and emails you **30 days, 14 days and 1 day before** each one expires, plus on the
expiry day.

It runs as a single Docker container. Admins SSH into the server and manage reminders with a
normal-looking command:

```text
$ expiry list
 ID   Name                               Expires      Days left   Source   Notes
 ──────────────────────────────────────────────────────────────────────────────────────────
 12   Payroll API [secret: prod]         01/10/2026           1   entra
  4   SSL portal.example.com             14/10/2026          14   ssl
  2   Payroll API cert                   20/10/2026          20   manual   renew via DigiCert
  9   Domain example.com                 30/09/2027         365   manual   renew at registrar
4 reminders · 3 expiring within 30 days   (today: 30/09/2026, Europe/Dublin)
```

---

## Quick start

**Just want to try it?** You need Docker and nothing else: no Microsoft 365 and no mail server.
Emails go to a local test inbox. Follow [Try it locally](#try-it-locally-linux-or-windows-wsl);
it takes about 5 minutes.

**Deploying for real?** Do these in order. Steps 1 and 2 are only needed for the features they
enable:

| # | Step | Needed when | Who |
|---|---|---|---|
| 1 | [Create the Entra app registration](#connect-to-entra-id) | you want Entra app secrets/certificates tracked, or email sent through Microsoft 365 | Entra admin (to grant consent) |
| 2 | [Create a sender mailbox + allow sending](#send-email-through-microsoft-365-graph) | you send email through Microsoft 365 (otherwise use any SMTP server) | Exchange admin |
| 3 | [Install on a Linux server](#install-on-a-linux-server) | always | server admin with `sudo` |
| 4 | Verify: `expiry config check --connect`, `expiry test-notify`, `expiry sync`, `expiry list` | always | |

Requirements: a Linux host (any distro, amd64 or arm64) with Docker, and network access to
Microsoft (Entra, email), the SSL hosts you track and any subnets you want to scan. See
[Network access](#network-access-firewall-rules) for the exact firewall rules.

---

## Contents

1. [How it works](#how-it-works)
2. [Features](#features)
3. [Try it locally](#try-it-locally-linux-or-windows-wsl)
4. [Publish the image (GitHub Container Registry)](#publish-the-image-github-container-registry)
5. [Install on a Linux server](#install-on-a-linux-server)
6. [Running on a Windows PC (WSL)](#running-on-a-windows-pc-wsl)
7. [Connect to Entra ID](#connect-to-entra-id)
8. [Send email through Microsoft 365](#send-email-through-microsoft-365-graph)
9. [Command reference](#command-reference)
10. [Configuration](#configuration)
11. [SSL certificates](#ssl-certificates)
12. [Backups and restore](#backups-and-restore)
13. [Self-monitoring alerts](#self-monitoring-alerts)
14. [Security notes](#security-notes)
15. [What is logged, and where](#what-is-logged-and-where)
16. [Adding more sources later](#adding-more-sources-later)
17. [Troubleshooting](#troubleshooting)
18. [Development](#development)
19. [License](#license)

---

## How it works

```text
             ┌──────────────────────── Docker container "expiry" ────────────────────────┐
 Entra ID ──▶│  sync (cron, every 6h)                                                     │
 (Graph API) │   ├─ entra: app registrations' secrets + certificates ─┐                  │
             │   └─ ssl:   connect to each host, read the certificate ─┤                  │
 domains/IPs▶│                                                        ▼                  │
             │                                       SQLite  /data/expiry.db              │
 SSH users ─▶│  expiry CLI (docker exec) ──add/edit/rm──▶  reminders, history, audit    │
             │                                                        │                  │
             │  check (cron, daily 08:00) ◀────────────────────────────┘                  │
             │   └─ due at 30 / 14 / 1 days / expiry day? ──▶ email (SMTP or Graph)      │──▶ inbox
             │                                              └─▶ webhooks (Teams/Slack)   │──▶ chat
             └────────────────────────────────────────────────────────────────────────────┘
```

* **Daemon.** The container's default command, `expiry daemon`, runs cron jobs. *sync*
  imports expiry dates from Entra ID and SSL hosts. *check* sends the notifications that are due.
  Both also run once at startup. *backup* snapshots the database nightly. *scan* (optional,
  weekly) [finds where your certificates are installed](#finding-certificates-automatically-ssl-scan)
  and tracks new locations. After every job, [self-monitoring](#self-monitoring-alerts) alerts
  you if expiry itself keeps failing.
* **CLI.** `/usr/local/bin/expiry` on the host is a tiny wrapper around
  `docker exec expiry expiry "$@"`, so anyone who can SSH in and use Docker can run
  `expiry list`, `expiry add ...` and so on. The wrapper passes the SSH user name so the audit log
  records who changed what.
* **Storage.** SQLite in a Docker volume. It needs no extra container, and the data is small: even
  thousands of reminders take kilobytes. WAL mode lets the CLI and the daemon use the database at
  the same time. PostgreSQL or Redis would add a second service to run and back up, for no benefit
  at this size.
* **Notifications are idempotent.** Each stage (30/14/1/0 days) is sent **once** per reminder and
  expiry date, so restarts or extra `expiry check` runs never produce duplicate emails. Failed
  deliveries are retried at the next check, **per destination**: if the email fails but a Teams
  webhook works, the next check retries only the email, and the failure still raises a
  self-monitoring alert (`expiry history` shows it as *partial*). Renewing an item (a new date) starts the cycle over.
  An item added late, for example with 5 days left, gets a single email for the tightest stage
  instead of three.

## Features

| Area | What you get |
|---|---|
| Reminders | name, expiry date, **days left** (color coded), notes, extra per-item recipients, mute |
| CLI | `list` `add` `show` `edit` `rm` `restore` · filters (`--within 30`, `--expired`, `--source`, `--search`) · `--json` output · relative dates (`+90d`, `+6m`, `+1y`) |
| Entra ID | client secrets **and** certificates of all app registrations; optional enterprise apps (SAML signing certs); include/exclude by name glob; optional **email to app owners**; portal link in the email |
| SSL/TLS | track any domain, IP (with SNI) or port; works with self-signed/expired/internal certs; `ssl check` inspector; **`ssl scan`** finds where your certificates are installed (wildcards included) by name guessing, subnets and certificate logs, and can track them automatically on a schedule; one email per certificate even when it's on many servers |
| Sync | new credentials → new reminders; renewed certs → date updated; deleted credentials → archived; items you remove stay removed |
| Notifications | email via **SMTP** or **Microsoft Graph**; HTML **Jinja2 template** + subject template; *individual* or *digest* mode; **Teams / Slack / generic webhooks** |
| Operations | `status` (heartbeat, last/next runs, health, errors), `history` (sent emails), `audit` (who changed what), `export`/`import` (JSON/CSV), `config check --connect`, `test-notify`, Docker HEALTHCHECK |
| Reliability | **nightly backups** with retention + `backup restore`; **self-monitoring alerts** when a sync, email delivery or backup keeps failing (e.g. expiry's own Entra secret expired) |
| Security | **certificate login** for the Entra app (`entra cert-create`); image **scanned for vulnerabilities** before publishing + weekly; SBOM + build provenance; Dependabot security alerts; non-root container, read-only config |
| Docs | `expiry --help`, `expiry help <command>`, `expiry <command> --help`, `man expiry` |

---

## Try it locally (Linux or Windows WSL)

You need Docker. If you already have it, skip to [Run the test stack](#run-the-test-stack).

**Option A: Docker Engine on Linux or inside WSL.** These are the steps for RHEL-family distros
(AlmaLinux, Rocky, RHEL). For Ubuntu/Debian see <https://docs.docker.com/engine/install/>.

```bash
# 1. WSL only: systemd must be enabled (needed for the docker service)
cat /etc/wsl.conf        # should contain:  [boot]  systemd=true
# if not:
printf '[boot]\nsystemd=true\n' | sudo tee /etc/wsl.conf
# then in PowerShell:  wsl --shutdown   and reopen your distro

# 2. install Docker Engine
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker                      # activate the new group in this shell (or log out and in again)
docker run --rm hello-world        # "permission denied ... docker.sock" = the group is not active yet
```

**Option B: Docker Desktop** (Windows/macOS). On Windows, enable *Settings → Resources → WSL
integration* for your distro.

### Run the test stack

The dev stack builds the image from the source in this folder (tagged `expiry:dev`, local only,
never published) and runs it with generic test settings. Two public test hosts are already
configured as SSL targets. Email is **off** in the shared test config: use `expiry check --dry-run` to
see what would be sent. To send real test emails, set up
[Microsoft 365 sending](#send-email-through-microsoft-365-graph) (the Entra app with `Mail.Send`,
exactly like production) and put the sender mailbox plus `email.enabled: true` in your own
`config.local.yaml` (below), with the `ENTRA_*` values in `config/expiry.env`.

**Which config file is used where:**

| File | Used by | In git? | Put in it |
|---|---|---|---|
| [`config/config.dev.yaml`](config/config.dev.yaml) | the local test stack, by default | yes (public) | nothing private: generic test settings (email off, public test sites) so anyone who clones can try it |
| `config/config.local.yaml` | the local test stack, when `.env` says so | **no** (git-ignored) | **your** test settings: real recipients, Graph sender, Entra, your company's hosts |
| `.env` | Docker Compose, locally | **no** (git-ignored) | one line, `EXPIRY_DEV_CONFIG=config.local.yaml`, to use your file instead of `config.dev.yaml` |
| `config/expiry.env` | the local test stack | **no** (git-ignored) | test secrets (`ENTRA_*`), copied from `config/expiry.env.example` |
| `/etc/expiry/config.yaml` + `/etc/expiry/expiry.env` | **a real server** | not in the repo | your production settings and secrets; created by the installer from `config.example.yaml` |

To use your own test settings: `cp config/config.dev.yaml config/config.local.yaml`, edit it, then
`echo EXPIRY_DEV_CONFIG=config.local.yaml > .env` and run `docker compose -f docker-compose.dev.yml up -d`.
None of the local files are used on a server.

```bash
git clone https://github.com/devlossantos/expiry.git && cd expiry
docker compose -f docker-compose.dev.yml up -d --build
docker logs -f expiry                  # Ctrl+C to stop following

# install the `expiry` command + man page into WSL (same as on a real server)
sudo dnf -y install man-db             # if `man` is missing (Ubuntu: sudo apt install man-db)
docker run --rm -u 0 \
  -v /usr/local/bin:/host/bin \
  -v /usr/local/share/man/man1:/host/man \
  expiry:dev install
```

### Try every command

```bash
expiry --help
man expiry
expiry status

# manual reminders
expiry add "Payroll API cert" +14d renew via DigiCert portal
expiry add github-pat +1d --notify dev@example.com
expiry add "Domain example.com" 30/09/2027 --notes "renew at registrar"
expiry list
expiry list --within 30
expiry show 1
expiry edit 1 --append-note "owner: platform team"
expiry edit 1                          # interactive
expiry check --dry-run                 # what would be sent
expiry check                           # send now (needs email configured, see above)
expiry history
expiry rm 3

# SSL
expiry ssl check github.com
expiry ssl add example.com www.microsoft.com:443
expiry ssl list
expiry ssl discover badssl.com         # finds subdomains via Certificate Transparency logs
expiry ssl scan --domain badssl.com --no-logs   # finds where certificates are installed (see "ssl scan")
expiry ssl rm example.com

# sync, admin
expiry sync
expiry audit
expiry test-notify --to you@example.com
expiry export -f csv
expiry config show
expiry config check
```

To test **Entra** from WSL, first create the app registration (see [Connect to Entra ID](#connect-to-entra-id)).
Then:

```bash
cp config/expiry.env.example config/expiry.env   # fill in ENTRA_TENANT_ID / CLIENT_ID / CLIENT_SECRET (git-ignored)
# set  sources.entra.enabled: true  in config/config.dev.yaml (or in your config.local.yaml)
docker compose -f docker-compose.dev.yml up -d   # re-creates the container with the new env
expiry config check --connect
expiry sync --source entra --dry-run
expiry sync && expiry list --source entra
```

Stop with `docker compose -f docker-compose.dev.yml down`. The data is kept. Adding `-v` also
**deletes the test database**.

---

## Publish the image (GitHub Container Registry)

*This section is for maintainers of this repo or of a fork. To deploy, skip to
[Install on a Linux server](#install-on-a-linux-server).*

The image is built and published automatically by GitHub Actions
([.github/workflows/docker-publish.yml](.github/workflows/docker-publish.yml)) to
**ghcr.io/devlossantos/expiry**, for both Intel (amd64) and ARM (arm64) servers. There are no
secrets to set up; the workflow uses the built-in `GITHUB_TOKEN`.

Every run checks: **tests on Python 3.10–3.13**, **lint** (ruff for Python, shellcheck for the
scripts), a **smoke test of the built image** (version, installer, daemon starts healthy, CLI
works, no errors in the logs) and the **vulnerability scan**. Nothing is published if any fails.

| You do | Checks | Published |
|---|---|---|
| open a pull request | ✔ | nothing |
| push to `main` | ✔ | image `:edge` (latest development build) |
| push a tag `v1.2.3` | ✔ | images `:1.2.3`, `:1.2`, `:latest` + a **GitHub Release** page with notes generated from the commits |

**Versions come from the git tag.** There is no version number to edit in any file: tag `v1.2.3`
makes the app report `1.2.3` (`expiry --version`, `expiry status`). Development builds report the
distance from the last release, e.g. `1.2.4.dev3+g88508e1` (3 commits after 1.2.3, at commit
`88508e1`).

Make a release, once `main` is green in the **Actions** tab:

```bash
git tag v1.0.1
git push origin v1.0.1
```

Which number? `MAJOR.MINOR.PATCH`: bug fixes only → **patch** (1.0.1), new features that don't
break anything → **minor** (1.1.0), changes that require users to change their config or setup →
**major** (2.0.0). Not every commit needs a release: tag when a set of changes is ready for servers.

Follow it under the repo's **Actions** tab. The image then appears under **Packages** on the repo
page. The package takes the repo's visibility: public repo, public image, and anyone can
`docker pull` it without logging in. If a fork's package shows as private, change it once under
*Package settings → Danger zone → Change visibility*.

## Install on a Linux server

### Private image only: log in first

The official image is public, so no login is needed; skip to [Install](#install). If you run your
own **private** fork, each server must log in once to pull it:

1. Use a GitHub account with **read access to the repo**.
2. Create a token: GitHub → *Settings → Developer settings → Personal access tokens → **Tokens
   (classic)** → Generate new token*, with **only** the `read:packages` scope and an expiry date.
   Track that expiry with `expiry add "GHCR pull token" <date>`.
3. On the server:

   ```bash
   sudo docker login ghcr.io -u <github-username>    # paste the token as the password
   ```

   The login is needed only to pull (install and upgrade), not to run.
   `sudo docker logout ghcr.io` removes the stored credential.

### Install

> **On a server you only edit two files:** `/etc/expiry/config.yaml` (settings) and
> `/etc/expiry/expiry.env` (secrets), both created by step 1. The repo's `config/config.dev.yaml`
> and `config/config.local.yaml` are only for the [local test stack](#run-the-test-stack) and are
> never used on a server. You don't even need the repo there. If you tested locally, copy your
> settings (recipients, Graph sender, SSL hosts, scan domains) from `config.local.yaml` into
> `/etc/expiry/config.yaml`.

Four steps on any Linux host with Docker. `:latest` is the newest release; pin a version
such as `ghcr.io/devlossantos/expiry:1.0.0` for predictable upgrades:

```bash
# 1. install the `expiry` command, the man page and a starter config into /etc/expiry
sudo docker run --rm -u 0 \
  -v /usr/local/bin:/host/bin \
  -v /usr/local/share/man/man1:/host/man \
  -v /etc/expiry:/host/config \
  ghcr.io/devlossantos/expiry:latest install

# 2. edit the settings (see the checklist below)
sudo nano /etc/expiry/config.yaml     # recipients, email, timezone, sources
sudo nano /etc/expiry/expiry.env      # secrets (root-only, chmod 600, never in config.yaml)

# 3. a folder for the nightly backups, owned by the container user (uid 10001)
sudo install -d -o 10001 -g 10001 -m 750 /var/backups/expiry

# 4. start the service (sudo is required: expiry.env is readable by root only)
sudo docker run -d --name expiry --restart unless-stopped \
  --log-opt max-size=10m --log-opt max-file=5 \
  --env-file /etc/expiry/expiry.env \
  -v /etc/expiry:/config:ro \
  -v expiry-data:/data \
  -v /var/backups/expiry:/backups \
  ghcr.io/devlossantos/expiry:latest
```

**Step 2 checklist.** The starter config is fully commented. At minimum, set:

| File | Setting | Example |
|---|---|---|
| `config.yaml` | `timezone` / `date_format` | `Europe/Dublin` / `"%d/%m/%Y"` |
| `config.yaml` | `notify.emails`: who receives reminders | `[it-ops@yourcompany.com]` |
| `config.yaml` | `email.transport` + its block | `graph` + `graph.sender: expiry@yourcompany.com` ([setup](#send-email-through-microsoft-365-graph)), or `smtp` + `email.from` + `email.smtp.*` |
| `config.yaml` | `sources.entra.enabled` | `true` once the Entra app exists ([setup](#connect-to-entra-id)) |
| `config.yaml` | `sources.ssl.hosts` (optional) | `[www.yourcompany.com]`, or add later with `expiry ssl add` |
| `expiry.env` | `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` | from the app registration |
| `expiry.env` | `SMTP_USERNAME`, `SMTP_PASSWORD` | only for `transport: smtp` with authentication |

Check it (if you are not in the `docker` group yet, prefix with `sudo`, see
[Who can use the expiry command](#who-can-use-the-expiry-command)):

```bash
expiry status                   # Daemon: running
expiry config check --connect   # validates config, signs in to Entra
expiry test-notify              # sends a sample email
expiry sync && expiry list
```

Changed `expiry.env` later? Docker reads it only when a container is created: run
`sudo docker rm -f expiry` and repeat step 4. Changes to `config.yaml` apply without a restart,
except `schedule` and `timezone` (`sudo docker restart expiry`).

Prefer Compose? After step 1 and 2 run `docker compose up -d` with the
included [docker-compose.yml](docker-compose.yml).

**Upgrading:** `docker pull ghcr.io/devlossantos/expiry:latest && docker rm -f expiry`, then repeat step 4. The data lives in
the `expiry-data` volume, so it is kept. Re-run step 1 to refresh the wrapper and man page; it
never overwrites your config.

**Where the data lives:** the SQLite database is in the Docker volume `expiry-data`, which is on
the server's disk at `/var/lib/docker/volumes/expiry-data/_data/`. It survives container
restarts, upgrades and `docker rm`. It is deleted **only** by `docker volume rm expiry-data` or
`docker compose down -v`. No secrets are stored in it.

**Backups:** automatic every night to `/var/backups/expiry` (the folder from step 3); see
[Backups and restore](#backups-and-restore).

### Network access (firewall rules)

expiry runs in a container, but to the rest of the network **every connection comes from the
server's IP address**: Docker NATs container traffic behind the host. Firewall rules and IDS
allow-lists are therefore about the **server's IP**, not the container.

| From (server IP) to | Port | Needed for |
|---|---|---|
| `login.microsoftonline.com`, `graph.microsoft.com` | TCP 443 | Entra sync, and email with `transport: graph` |
| your SMTP server | TCP 587 / 465 / 25 | email with `transport: smtp` |
| Teams / Slack webhook hosts | TCP 443 | webhooks, if used |
| every SSL host you track | its port (443, 993, ...) | reading certificates (`ssl add`, sync) |
| internal DNS servers | UDP + TCP 53 | resolving host names and reverse DNS |
| `crt.sh` | TCP 443 | `ssl discover` / `ssl scan` certificate logs (optional) |
| **each subnet you scan** (`sources.ssl.scan.networks`) | **each port in `ports`** | `ssl scan --network` |

**Scanning subnets.** Ask your network/security team for:

> Allow TCP from `10.0.5.20` (expiry server) to `10.1.2.0/24` and `10.1.3.0/24` on ports
> `443, 8443`, and DNS to the internal resolvers. Add `10.0.5.20` to the IDS/IPS allow-list as
> an authorised certificate scanner (weekly, Monday 05:00, TLS handshakes only).

Also check the **target servers' own firewalls** (e.g. Windows Firewall, host iptables), which
must accept connections from the server on those ports.

**Firewall on the expiry server itself.** Docker **forwards** container traffic, so host
*outbound* rules (the `OUTPUT` chain, `ufw allow out`) don't apply to it, and Docker allows it
by default. Only if your server deliberately restricts container egress do the rules belong in
Docker's `DOCKER-USER` chain, for example:

```bash
# the container's address (172.17.x.x with `docker run`; Compose uses its own network)
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' expiry
# allow the expiry container (here the default bridge 172.17.0.0/16) to reach a scan subnet on 443/8443
sudo iptables -I DOCKER-USER -s 172.17.0.0/16 -d 10.1.2.0/24 -p tcp -m multiport --dports 443,8443 -j ACCEPT
```

**DNS inside the container.** Docker gives the container the server's DNS servers. If internal
names resolve on the server but not in the container, set them explicitly: add
`--dns 10.0.0.53 --dns-search example.com` to `docker run` (or `dns:` / `dns_search:` in Compose).

**Test before scanning a whole range:**

```bash
getent hosts wiki.example.com                  # DNS on the server
docker exec expiry python -c "import socket; print(socket.gethostbyname('wiki.example.com'))"   # DNS in the container
timeout 3 bash -c '</dev/tcp/10.1.2.10/443' && echo reachable                                  # TCP from the server
expiry ssl check 10.1.2.10                    # TLS from the container: shows the certificate
expiry ssl scan --domain example.com --network 10.1.2.0/28 --no-logs   # a small range first
```

A blocked port just shows up as "nothing found" at that address (connections time out after 3
seconds), so an empty scan result for a subnet usually means a firewall rule is missing.

### Who can use the `expiry` command

The wrapper calls `docker`. Choose one:

* Add trusted admins to the `docker` group: `sudo usermod -aG docker alice`. Note that docker
  group membership is effectively root.
* Or, more restricted, allow only the wrapper through sudo. Users still just type `expiry list`:
  the wrapper notices they can't reach Docker and re-runs itself through this sudo rule, and the
  audit log still records their own name:

  ```bash
  sudo groupadd expiry-users && sudo usermod -aG expiry-users alice
  echo '%expiry-users ALL=(root) NOPASSWD: /usr/local/bin/expiry' | sudo tee /etc/sudoers.d/expiry
  sudo chmod 440 /etc/sudoers.d/expiry && sudo visudo -c    # validate
  ```

  Users must log out and in again to pick up the new group.

---

## Running on a Windows PC (WSL)

expiry runs fine in **WSL** (Windows Subsystem for Linux), which is Linux, so the
[install](#install-on-a-linux-server) is the same. Three things are different on a Windows PC:

**1. Keep WSL running.** WSL shuts down shortly after its last terminal closes, and expiry with it.
This task starts WSL hidden in the background at every login. In PowerShell:

```powershell
$action   = New-ScheduledTaskAction -Execute "conhost.exe" -Argument "--headless wsl.exe -d AlmaLinux-10 --exec sleep infinity"
$trigger  = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "WSL keep-alive" -Action $action -Trigger $trigger -Settings $settings
Start-ScheduledTask -TaskName "WSL keep-alive"
(Get-ScheduledTask "WSL keep-alive").State      # Running
```

Replace `AlmaLinux-10` with your distribution (`wsl -l -v`). WSL starts Docker (systemd must be
enabled: `[boot] systemd=true` in `/etc/wsl.conf`), and Docker starts expiry
(`--restart unless-stopped`). You never start expiry by hand. For a machine that should run without
anyone logged in, use `-AtStartup` instead of `-AtLogOn`, and register the task with the account's
password (`-User ... -Password ...`, "run whether user is logged on or not").

**2. Schedule for a PC that isn't always on.** The default schedule suits a server that is always
on. A backup or scan missed while the PC was off is caught up automatically (at start-up and after
each check), but reminders are only checked on schedule, so check more often. In
`/etc/expiry/config.yaml`:

```yaml
schedule:
  sync: "0 * * * *"          # every hour while the PC is on
  check: "15 * * * *"        # every hour: each reminder is still sent only once
  run_on_start: true         # catch up at every start
backup:
  schedule: "30 12 * * *"    # daily at 12:30
# sources.ssl.scan.schedule: "0 10 * * 1"   (Mondays 10:00, if you use the weekly scan)
```

Then `expiry config check` and `sudo docker restart expiry`.

While the PC is off nothing runs. Reminders that became due in the meantime are sent at the next
start (they're late, not lost), and nobody else gets reminders or alerts during that time. If
people rely on the reminders, run expiry on a machine that is always on.

**3. Networking, backups, access.**
* Traffic to the network (Entra, email, SSL hosts, subnet scans) comes **from the PC's IP**, so
  firewall rules and allow-lists use the PC's address ([Network access](#network-access-firewall-rules)).
  With a corporate VPN or unreliable DNS inside WSL, set `networkingMode=mirrored` and
  `dnsTunneling=true` under `[wsl2]` in `%UserProfile%\.wslconfig`, then `wsl --shutdown`.
* The backups in `/var/backups/expiry` live on the same PC. Copy them to a Windows or network
  folder daily, e.g. in `/etc/cron.d/expiry-backup-copy` (needs `cronie` enabled):
  `0 13 * * * root cp -u /var/backups/expiry/*.db /mnt/c/Backups/expiry/`
* A WSL distribution belongs to one Windows user, so other admins can't use the `expiry` command
  on your PC. For a shared setup, use a server.
* Make sure the PC doesn't sleep while you rely on it (`powercfg /change standby-timeout-ac 0`).

---

## Connect to Entra ID

expiry needs an **app registration** with read access to other app registrations. It reads the
credential *metadata* only (name, hint and end date). Microsoft Graph never returns secret values.

### With the script (Azure CLI)

Run it from a clone of this repo, on any machine with the
[Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli). It doesn't need to be the
server:

```bash
git clone https://github.com/devlossantos/expiry.git && cd expiry
az login --allow-no-subscriptions          # as Global Admin / Privileged Role Admin
sh scripts/entra-setup.sh                  # read-only
sh scripts/entra-setup.sh --mail --owners  # + send mail via Graph, + email app owners
```

It prints `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID` and `ENTRA_CLIENT_SECRET` for `/etc/expiry/expiry.env`.

### In the portal

1. **Entra admin center** (<https://entra.microsoft.com>) → *Identity → Applications → App registrations → New registration*.
   Name it `expiry-monitor`, choose *Accounts in this organizational directory only*, leave the
   Redirect URI empty, and click *Register*.
2. On the **Overview** page, copy the *Directory (tenant) ID* and the *Application (client) ID*.
3. *API permissions → Add a permission → Microsoft Graph → **Application permissions***:

   | Permission | Needed for |
   |---|---|
   | `Application.Read.All` | **required**: read app registrations and enterprise apps with their credential end dates |
   | `User.ReadBasic.All` | optional: `sources.entra.notify_owners: true` (owner email addresses) |
   | `Mail.Send` | optional: `email.transport: graph`. Read [Send email through Microsoft 365](#send-email-through-microsoft-365-graph) first; the scoped Exchange setup there is preferred over this tenant-wide grant |

   Then click **Grant admin consent for \<tenant\>**. The status must show green checkmarks.
4. *Certificates & secrets → Client secrets → New client secret*. Copy the **Value** (not the
   Secret ID) right away.
   expiry will read this secret's own expiry too, so it reminds you to rotate its own credentials.
   Better, once it runs: switch to a [certificate](#certificate-login-recommended) instead of a secret.
5. Fill `/etc/expiry/expiry.env`:

   ```ini
   ENTRA_TENANT_ID=00000000-0000-0000-0000-000000000000
   ENTRA_CLIENT_ID=11111111-1111-1111-1111-111111111111
   ENTRA_CLIENT_SECRET=the-secret-value
   ```

6. In `/etc/expiry/config.yaml` set `sources.entra.enabled: true`. Docker reads `--env-file`
   only when it creates a container, so re-create it: `sudo docker rm -f expiry`, then run
   install step 4 again. Then:

   ```bash
   expiry config check --connect
   expiry sync --source entra --dry-run
   expiry sync
   expiry list --source entra
   ```

### Certificate login (recommended)

A client secret is a password: whoever gets the string can sign in as your app, from anywhere, until
it expires. With a certificate only the **public** part is uploaded to Entra and the private key never
leaves your server. Microsoft recommends certificates for app authentication, and Secure Score flags
app secrets. Switching takes about 5 minutes:

```bash
# 1. create a key + certificate inside the container's data volume (private key: mode 600)
expiry entra cert-create                       # /data/entra-auth.pem + /data/entra-auth.crt, valid 2 years

# 2. copy the PUBLIC certificate to your PC and upload it to the app registration
sudo docker cp expiry:/data/entra-auth.crt .   # or: expiry entra cert-show --pem  (copy/paste)
#    Entra admin center > App registrations > expiry-monitor > Certificates & secrets >
#    Certificates > Upload certificate > entra-auth.crt
#    (Azure CLI alternative: az ad app credential reset --id <client-id> --cert @entra-auth.crt --append)
```

3. In `/etc/expiry/config.yaml` set `entra.certificate_path: /data/entra-auth.pem` and remove
   `client_secret` (or empty `ENTRA_CLIENT_SECRET` in `expiry.env`). The thumbprint is read from the
   file; no need to configure it.
4. `expiry config check --connect` should sign in. `expiry status` shows
   `Entra login: certificate (expires ...)`.
5. Delete the old client secret in the app registration.

The certificate itself is tracked like every other app credential (it appears as
`expiry-monitor [cert: ...]`), so you get the usual 30/14/1-day reminders before it expires. To
renew: `expiry entra cert-create --force`, upload the new `.crt`, and remove the old certificate in
Entra. The key lives in the `expiry-data` volume, not in backups. If it's lost, create a new one.

### What you get

Every secret and certificate becomes a reminder named like `Payroll API [secret: prod]` or
`Payroll API [cert: CN=payroll]`. Notes, mute and extra recipients you add to these reminders
survive every sync. When a secret is deleted in Entra, its reminder is archived. When you add a new
secret, a new reminder appears.

---

## Send email through Microsoft 365 (Graph)

If you use Microsoft 365, the recommended way to send is **Microsoft Graph with the same app
registration**. There is no SMTP server or password to manage, and it works with MFA and with
Microsoft's retirement of SMTP basic authentication. You need:

1. a **mailbox to send from**
2. **permission** for the app registration to send as that mailbox
3. `email.transport: graph` in the config

> Testing locally? The same setup works for the local test stack: put the sender in your
> `config.local.yaml` (see [Run the test stack](#run-the-test-stack)).

### 1. Create the sender mailbox

**Exchange admin center** (<https://admin.exchange.microsoft.com>) → *Recipients → Mailboxes →
**Add a shared mailbox***. For example:

| Field | Value |
|---|---|
| Display name | `Expiry Monitor`, which recipients see as the sender |
| Email address | `expiry@example.com` |

A **shared mailbox needs no license** and has no password. You can also use an existing mailbox.

Or with Exchange Online PowerShell:

```powershell
Connect-ExchangeOnline
New-Mailbox -Shared -Name "Expiry Monitor" -DisplayName "Expiry Monitor" -PrimarySmtpAddress expiry@example.com
```

### 2. Allow the app registration to send mail. Choose A or B

#### Option A: Entra `Mail.Send` (quick, tenant-wide)

App registration → *API permissions → Add a permission → Microsoft Graph → **Application
permissions** → `Mail.Send`* → **Grant admin consent**. (`sh scripts/entra-setup.sh --mail` does
the same.)

> ⚠️ This lets the app send as **any mailbox in the tenant**. It's fine for a quick test; for
> production use option B.

#### Option B: Exchange RBAC for Applications (recommended, one mailbox only)

This grants `Mail.Send` **only for the sender mailbox**. Do **not** add `Mail.Send` in Entra for this
option, because Entra and Exchange grants add together and the tenant-wide grant would still apply.

You need two IDs:

* `<CLIENT_ID>`: App registration → Overview → *Application (client) ID*
* `<SP_OBJECT_ID>`: **Enterprise applications** → `expiry-monitor` → Overview → *Object ID*.
  This is the service principal, **not** the Object ID shown on the app registration page.

Run in PowerShell as an Exchange administrator:

```powershell
# One-time: install the module
Install-Module ExchangeOnlineManagement -Scope CurrentUser

Connect-ExchangeOnline

# 1. Register the app's service principal in Exchange
New-ServicePrincipal -AppId <CLIENT_ID> -ObjectId <SP_OBJECT_ID> -DisplayName "expiry-monitor"

# 2. A scope that matches only the sender mailbox
New-ManagementScope -Name "Expiry sender" `
  -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'expiry@example.com'"

# 3. Grant Mail.Send for that scope only
New-ManagementRoleAssignment -App <CLIENT_ID> -Role "Application Mail.Send" `
  -CustomResourceScope "Expiry sender"

# 4. Verify: InScope should be True for the sender...
Test-ServicePrincipalAuthorization -Identity <CLIENT_ID> -Resource expiry@example.com
# ...and False for any other mailbox
Test-ServicePrincipalAuthorization -Identity <CLIENT_ID> -Resource someone.else@example.com
```

Permission changes can take **30 minutes to 2 hours** to apply. `403 ErrorAccessDenied` right
after running these usually just means it hasn't applied yet.

Moving from option A to B? Remove `Mail.Send` from the app registration (*API permissions → … →
Remove permission*) after the Exchange assignment is in place.

To undo option B later:

```powershell
Get-ManagementRoleAssignment -RoleAssignee <CLIENT_ID> | Remove-ManagementRoleAssignment
Remove-ManagementScope "Expiry sender"
Remove-ServicePrincipal -Identity <CLIENT_ID>
```

### 3. Configure expiry

In `/etc/expiry/config.yaml` (or `config/config.dev.yaml` for the local stack):

```yaml
notify:
  emails:
    - it-ops@example.com          # who receives the reminders

email:
  enabled: true
  transport: graph
  graph:
    sender: expiry@example.com    # the mailbox from step 1
```

Graph uses the same `ENTRA_TENANT_ID` / `ENTRA_CLIENT_ID` / `ENTRA_CLIENT_SECRET` as the Entra
sync. `email.from` and the `smtp` block are ignored with this transport. Config changes apply
without a restart.

### 4. Test

```bash
expiry config check
expiry test-notify --to you@example.com    # check Junk the first time
expiry check --dry-run                     # what would be sent now
expiry history                             # sent / failed notifications with errors
```

| Error | Meaning |
|---|---|
| `403 ErrorAccessDenied` / `Access is denied` | no `Mail.Send` consent, or the option B assignment has not applied yet |
| `404 ResourceNotFound` / `MailboxNotEnabledForRESTAPI` | `graph.sender` is not an existing Exchange Online mailbox |
| `401` / `AADSTS…` | wrong tenant ID, client ID or secret |

### Alternative: SMTP

Any SMTP server works with `transport: smtp` (settings in `email.smtp`, password in
`expiry.env`). This includes an internal relay, SendGrid or Mailgun. For Office 365 SMTP AUTH
(`smtp.office365.com:587`) you need a licensed mailbox with SMTP AUTH enabled. Microsoft is
retiring basic authentication for it, so Graph is preferred.

---

## Command reference

Every command has `--help`, and `expiry help <command>` works too.

| Command | Description |
|---|---|
| `expiry list [-a] [-s manual\|entra\|ssl] [-w DAYS] [-e] [-q TEXT] [--json]` | List reminders, soonest first, with days left. Alias `ls` |
| `expiry add NAME DATE [NOTES...] [-n TEXT] [--notify EMAIL] [--mute]` | Add a reminder. DATE = `DD/MM/YYYY` (the `date_format`), `YYYY-MM-DD`, or `+30d`/`+2w`/`+6m`/`+1y` |
| `expiry show ID [--json]` | Details, recipients, notification schedule, history |
| `expiry edit ID [--name] [-d DATE] [-n NOTES] [--append-note] [--notify/--add-notify/--clear-notify] [--mute/--unmute]` | Edit; interactive when run without options |
| `expiry rm ID [ID...] [-y]` | Remove (manual: delete; synced: ignore). Aliases `remove`, `delete` |
| `expiry restore ID` | Un-ignore / un-archive |
| `expiry ssl add HOST[:PORT]... [--sni NAME] [--name] [-n NOTES] [-f]` | Track certificates of domains/IPs |
| `expiry ssl list` · `ssl rm TARGET` · `ssl check HOST` · `ssl discover DOMAIN [--add]` | Manage / inspect / discover SSL targets |
| `expiry ssl scan [-d DOMAIN] [-n NAME] [--names-file FILE\|-] [--network CIDR] [-p PORTS] [--wildcards] [--add]` | Find where your certificates (incl. wildcards) are installed |
| `expiry sync [-s entra\|ssl] [--dry-run]` | Import from sources now |
| `expiry check [--dry-run]` | Send due notifications now |
| `expiry test-notify [--to EMAIL]` | Send a sample email / webhook |
| `expiry status` · `history` · `audit` | Service health, sent notifications, change log |
| `expiry export [-f json\|csv] [-a] > FILE` · `import - < FILE` | Export / bulk import (CSV dates may use your `date_format`) |
| `expiry config show` · `config check [--connect]` | Effective config (secrets masked) / validation |
| `expiry backup create` · `backup list` · `backup restore FILE` | Database backups (automatic nightly) |
| `expiry entra cert-create` · `entra cert-show [--pem]` | Certificate login for the Entra app |
| `expiry daemon` · `health` · `install` | Container internals |

---

## Configuration

`/etc/expiry/config.yaml` is fully commented; see [config/config.example.yaml](config/config.example.yaml).
Values like `${NAME}` come from `/etc/expiry/expiry.env`. The highlights:

```yaml
timezone: Europe/Dublin        # IANA name (not "Ireland/Dublin")
date_format: "%d/%m/%Y"        # 31/12/2026; or "%Y-%m-%d", "%d %b %Y"
schedule:
  sync: "0 */6 * * *"          # cron
  check: "0 8 * * *"           # daily at 08:00
notify:
  days_before: [30, 14, 1]     # one month, two weeks, the day before
  on_expiry_day: true
  mode: individual             # or digest: one email per run with all due items
  emails: [it-ops@example.com, security@example.com]
  webhooks:
    - {format: teams, url: "${TEAMS_WEBHOOK_URL}"}
email:
  transport: smtp              # or graph
  from: "Expiry Monitor <expiry@example.com>"
  subject: "[Expiry] {{ item.name }} expires {{ item.when }}"
  template_file: /config/templates/reminder.html.j2
```

**Email template.** The installer copies the default HTML template to
`/etc/expiry/templates/reminder.html.j2`. Edit it and set `email.template_file`. Available
variables are `items` (list), `item` (first item), `count` and `today`. Each item has `name`,
`expires_on`, `expires_on_long`, `days_left`, `when` ("in 14 days"), `expired`, `severity`,
`stage_label`, `notes`, `source`, `url` and `meta`. Preview it with `expiry test-notify`.

**Dates.** `date_format` controls how dates are shown in the CLI, emails and logs, and the format
you type (`expiry add x 31/12/2026`). `YYYY-MM-DD` and `+90d` always work too. `--json` and `export`
always use `YYYY-MM-DD` so scripts and spreadsheets are unambiguous.

Most config changes apply at the next run. `schedule`, `timezone` and changes in `expiry.env` need
a container restart or re-create.

---

## SSL certificates

```bash
expiry ssl add example.com                        # port 443
expiry ssl add mail.example.com:993 ldap.corp:636 # any TLS port
expiry ssl add 10.0.0.15 --sni portal.example.com --notes "F5 VIP, cert on the LB"
expiry ssl add https://app.example.com/login      # URLs are fine
expiry ssl discover example.com --add             # find & track all public subdomains
expiry ssl check expired.badssl.com               # inspect without saving
```

* expiry reads the certificate the server actually presents. It needs no trust chain, so
  self-signed, internal-CA and already-expired certificates work. `ssl check` and `ssl add` still
  tell you whether the certificate is trusted.
* Each sync refreshes the dates. When a certificate is renewed, the reminder's date changes and
  the 30/14/1 cycle starts over.
* A host that can't be reached during a sync keeps its last known date. The error shows up in
  `expiry sync` and `expiry status`.
* You can also list hosts in the config (`sources.ssl.hosts`), which is handy for
  configuration-as-code.
* `discover` queries the public Certificate Transparency log search at crt.sh, so it only finds
  names that have had publicly trusted certificates. For internal names use `ssl scan`.

### Finding certificates automatically (`ssl scan`)

Typing in every server is error-prone, especially for a **wildcard** certificate installed on
several servers. `expiry ssl scan` finds them for you:

```bash
expiry ssl scan --domain example.com                           # typical names + certificate logs
expiry ssl scan --domain example.com --name erp --name hr      # plus your own host names
expiry ssl scan --domain example.com --names-file - -y < dns-names.csv   # plus all names from a DNS export
expiry ssl scan --domain example.com --network 10.1.2.0/24     # plus every address of a subnet
expiry ssl scan --domain example.com --ports 443,8443,9443,5001   # other ports (default 443,8443,9443)
expiry ssl scan --domain example.com --wildcards --add         # only wildcards, and track them
```

```text
 Certificate          Issuer          Expires      Days left   Location           Found via            Tracked
 *.example.com wildcard  GoDaddy ...  31/05/2027         243   wiki.example.com:443  name 10.1.2.10    new
                                                               10.1.2.150:443        network           new
```

**What it does in the background:**
1. **Names:** it builds a list of about 180 typical server names (`www`, `mail`, `vpn`, `wiki`,
   `portal`, `intranet`, ...) under each domain, plus your own names (`--name`, `--names-file`) and the
   public names found in certificate logs (crt.sh). It looks each one up in DNS. On the server that
   means your internal DNS, so internal-only names are found too.
2. **Subnets (only if you list them):** it goes through every address of each range. It reads the
   certificate without asking for a name, and if that isn't yours, retries with the address's
   reverse-DNS name.
3. For every address and port (default **443, 8443, 9443**) it opens a TCP connection, does a
   **TLS handshake, reads the certificate and closes**, the same first step a browser takes. No HTTP request, no login and no
   data is sent. It runs 32 connections in parallel with a 3-second timeout each.
4. It keeps only certificates **issued for your domains** (name or SAN matches `example.com` or
   `*.example.com`) and groups them **by certificate**, so you see every server a wildcard is on.
   Nothing else is recorded: no open ports, no services, no vulnerabilities.

**Why a scan might miss servers.** A server is found by name only if its name is on the list
(built-in + yours) **and** resolves in DNS **and** serves TLS on one of the ports **and** is
reachable from where the scan runs. Application servers usually have their own names
(`crm-prod`, `app3`...) that no generic list can guess, and often run on other ports. To find
everything that uses a certificate, a wildcard especially:

1. **Scan the subnets** where your servers live (`--network`). This finds every address presenting
   the certificate, whatever its name. It needs [firewall access](#network-access-firewall-rules).
2. **Give it all your real host names** (`--names-file`), exported from your internal DNS:

   ```powershell
   # Windows DNS server (PowerShell, as a DNS admin) -> names.csv with a HostName column
   Get-DnsServerResourceRecord -ZoneName example.com -RRType A |
     Select-Object HostName | Export-Csv names.csv -NoTypeInformation
   Get-DnsServerResourceRecord -ZoneName example.com -RRType CName |
     Select-Object HostName | Export-Csv names.csv -NoTypeInformation -Append
   ```

   ```bash
   # BIND / Linux DNS (if zone transfers are allowed from your machine)
   dig axfr example.com @ns1.example.com > names.txt
   ```

   The file can be a plain list (one name per line, `#` comments), the Windows CSV or the BIND
   output. expiry takes the first column and ignores headers, `@`, SRV records (`_ldap._tcp`) and
   comments. Because the command runs inside the container, pipe the file in
   (`--names-file - -y < names.csv`), or put it in `/etc/expiry/` and use `/config/names.csv`.
3. **Add your application ports** (`--ports 443,8443,9443,5001`).

**On a schedule, adding what it finds** (`config.yaml`):

```yaml
sources:
  ssl:
    scan:
      enabled: true
      schedule: "0 5 * * 1"                     # weekly, Monday 05:00
      domains: [example.com]
      names: [erp, hr-portal]                   # optional extra names
      names_file: /config/scan-names.csv        # optional: /etc/expiry/scan-names.csv on the server
      networks: ["10.1.2.0/24", "10.1.3.0/24"]  # optional subnets
      ports: [443, 8443, 9443, 993, 636]        # default: 443, 8443, 9443
      add: true                                 # false = only report
```

After each scheduled scan you get an email listing any **new** locations (added, or "not tracked
yet" with `add: false`). The run is recorded in `expiry audit`, and `expiry status` shows the last
scan.

**One email per certificate:** when several servers use the same certificate (a wildcard, a
SAN certificate), their reminders are combined: *"Certificate \*.example.com expires in 14 days (3
servers)"*, listing every server. After you renew, a server still on the old certificate keeps
its own reminder, which is how forgotten servers are caught.

Notes:
* **Subnet scans connect to every address.** Tell your network/security team first, because
  intrusion-detection systems may flag it. The server needs firewall access to each subnet and
  port: see [Network access](#network-access-firewall-rules). Limit: 65,536 address × port
  combinations per scan.
* Ports must speak TLS directly (443, 8443, 993 IMAPS, 995, 465, 636 LDAPS...). STARTTLS ports
  (25/587 SMTP, 143 IMAP, 389 LDAP) are not supported yet.
* Run it where the servers are reachable (your Linux server on the company network). From
  elsewhere only public hosts are found.

---

## Backups and restore

The daemon backs up the database **every night at 02:30** (`backup.schedule`) and keeps the newest
**14** (`backup.keep`). Each backup is a consistent, integrity-checked snapshot taken while the
service runs. If the machine was off at that time, the missed backup runs automatically as soon as
the service is up again (the same goes for a missed weekly scan).

**Where:** to `/backups` inside the container when a host folder is mounted there (install step 3:
`/var/backups/expiry` on the server), otherwise to `/data/backups` inside the data volume. Prefer the
host folder, because a backup kept in the same volume is lost together with it. Copy
`/var/backups/expiry` to another machine or your backup system to protect against losing the whole
server.

```bash
expiry backup create                          # back up now
expiry backup list                            # newest first
expiry backup restore expiry-20261001-023000.db   # replace current data (asks first)
```

`restore` first saves the current database as `expiry-prerestore-<time>.db`, so a restore can be
undone by restoring that file. It works while the service runs. If a backup fails (full disk, wrong
folder permissions), you get a [self-monitoring alert](#self-monitoring-alerts).

What is **not** in a backup: `config.yaml` and `expiry.env` (they're on the host in
`/etc/expiry`; back that folder up too) and the Entra certificate key (create a new one if needed).
For a readable copy: `expiry export -a > reminders.json` (restore with `expiry import - < reminders.json`).

## Self-monitoring alerts

expiry watches its own work and tells you when **it** is broken, not only when your certificates
are. Typical case: the monitoring app's own Entra secret expired, so the sync fails and new
expiries stop being found.

| Component | Alert when |
|---|---|
| Entra ID sync / SSL sync | the whole sync fails **3 times in a row** (`alerts.sync_failures`; syncs run every 6h, so about 12–18h). One unreachable SSL host doesn't count; it shows in `expiry status` |
| Reminder delivery | a reminder email/webhook could not be delivered (first failure) |
| Database backup | a backup failed (first failure) |

Alerts go to `alerts.emails` (default: `notify.emails`) **and** to every webhook, so a Teams/Slack
webhook still reaches you when email is what's broken. The alert names the server
(`alerts.server_name`), the error and what to check. It repeats every 24h (`alerts.repeat_hours`)
while the problem lasts, and a **RESOLVED** message follows when it works again. `expiry status`
shows a `Health` line at any time.

The one thing expiry can't report is itself not running at all. The Docker health check marks the
container *unhealthy* and `--restart unless-stopped` restarts it after crashes. For full coverage,
point your existing server monitoring at `docker inspect -f '{{.State.Health.Status}}' expiry`.

---

## Security notes

* Secrets belong in `/etc/expiry/expiry.env` (root-owned, `chmod 600`, passed with
  `--env-file`), not in `config.yaml`. `expiry config show` masks them.
* The container runs as a non-root user (uid 10001) and mounts the config read-only.
* `Application.Read.All` is read-only and cannot reveal secret values.
* `Mail.Send` granted in Entra lets the app send as **any** mailbox. In production, use
  [option B](#option-b-exchange-rbac-for-applications-recommended-one-mailbox-only) (Exchange RBAC
  for Applications) so it can only send as the sender mailbox.
* Prefer [certificate login](#certificate-login-recommended) for the app registration in production.
* **Image supply chain:** every image is scanned with [Trivy](https://trivy.dev) before it's
  published. A critical vulnerability with a fix available, or a secret found in the image, blocks
  the release. The published `:latest` is re-scanned every Monday. Results are under the repo's
  **Security → Code scanning** tab. Images ship with an SBOM (list of contents) and signed build
  provenance, which you can check with `gh attestation verify oci://ghcr.io/devlossantos/expiry:latest -o devlossantos`.
  Dependabot **security** alerts/updates are enabled: a pull request only appears when a dependency
  has a known vulnerability (no routine version bumps). Each build uses the current `python:3.12-slim`
  base and dependency versions, gets the latest Debian security patches and contains no `pip`.
* Docker group membership is root-equivalent; use the sudoers rule above for regular users.

## What is logged, and where

| What | Where | How to see it |
|---|---|---|
| Every change to reminders and SSL targets: add, edit, remove, restore, sync updates, scan additions, backup restores, **with the user's name** (the SSH user, passed by the wrapper) or `sync:entra` / `scan` | database, `audit` table | `expiry audit` (`--json`, `-i ID`) |
| Every notification sent or failed, with recipients, channel and error | database, `notifications` table | `expiry history` |
| Each scan run (what was checked, what was found and added) | `audit` + last-run summary | `expiry audit`, `expiry status` |
| Service activity: startup, each sync/check/backup/scan with counts, warnings, errors with details, alerts sent | container output (stdout) | `docker logs expiry` (`--since 24h`, `-f`) |
| Current health: failing components, last error | database | `expiry status` |

Docker keeps the container output in `/var/lib/docker/containers/...`. The install command limits
it to 5 × 10 MB (`--log-opt max-size=10m --log-opt max-file=5`), so it never fills the disk. To keep
logs longer or centrally, use a Docker logging driver (syslog, journald, Splunk, ...).

**Not** logged: secret values, passwords or tokens (they are never read or stored), and the
individual connection attempts of a scan (only the per-run summary).

## Adding more sources later

A source is a small class with a `name` and a `fetch()` that returns items
(`external_id`, `name`, `expires_on`, `meta`). See [src/expiry/sources/base.py](src/expiry/sources/base.py)
and the two implementations, [entra.py](src/expiry/sources/entra.py) and [sslcert.py](src/expiry/sources/sslcert.py).
Register the class in [sources/\_\_init\_\_.py](src/expiry/sources/__init__.py) and add a
`sources.<name>` block to the config. Sync, archiving, notifications, the CLI and history then
work for it automatically. Good candidates:

* **STARTTLS services** in `ssl scan`/`ssl add` (SMTP 25/587, IMAP 143, LDAP 389, databases)
* **Domain registrations** via RDAP (the modern WHOIS): renewal dates of `example.com` itself
* Azure Key Vault secrets/certificates (`expires` attribute)
* AWS IAM access keys / ACM certificates
* GitHub PATs / deploy keys, GitLab tokens
* Apple push / developer certificates, domain registrations (RDAP/WHOIS)

## Troubleshooting

| Symptom | Fix |
|---|---|
| `expiry: no permission to use Docker` | add the user to `docker` group or use the sudoers rule |
| `container 'expiry' does not exist` | start it (install step 4); a different name → `export EXPIRY_CONTAINER=name` |
| `status` says *Daemon not running* | `docker logs expiry` |
| `HTTP 403 Authorization_RequestDenied` on sync | permission missing or **admin consent** not granted |
| `AADSTS7000215 invalid client secret` | you copied the *Secret ID*, not the *Value*, or it expired |
| emails not arriving | `expiry test-notify --to you@x.com`, check `expiry history` for the error, check Junk |
| Graph `403 ErrorAccessDenied` when sending | `Mail.Send` not consented, or the Exchange RBAC assignment is still applying (up to 2 h) |
| Graph `404 MailboxNotEnabledForRESTAPI` | `email.graph.sender` is not an Exchange Online mailbox |
| Office 365 SMTP `535 5.7.139` | SMTP AUTH is disabled for the mailbox/tenant, so use `transport: graph` |
| alert "Entra ID sync is failing" with `AADSTS7000222` / `AADSTS700027` | the app's secret or certificate expired / was removed: create a new one ([certificate login](#certificate-login-recommended)) |
| alert "Database backup is failing" with `Permission denied` | `sudo chown 10001:10001 /var/backups/expiry` |
| wrong "days left" | set `timezone` (e.g. `Europe/Dublin`) |
| `unknown timezone 'Ireland/Dublin'` | use the IANA name `Europe/Dublin` |

## Development

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"      # needs the git history (tags) for the version: expiry --version
pytest -q                    # the same tests CI runs on Python 3.10-3.13
pip install ruff && ruff check src tests      # lint (rules in pyproject.toml); `--fix` sorts imports
shellcheck scripts/*.sh                       # shell scripts
EXPIRY_DB=./dev.db EXPIRY_CONFIG=config/config.example.yaml expiry list
```

The command runs inside the container on a server, so files are passed through the wrapper:
`expiry import - < reminders.csv` and `expiry export -f csv > reminders.csv` (not `-o`/a path,
which would refer to the container's filesystem).

Layout:

```text
src/expiry/
  cli.py          click commands
  config.py       YAML + ${ENV} expansion + validation
  db.py           SQLite store (reminders, ssl_targets, notifications, audit, kv)
  checker.py      which stage is due, delivery, retry
  notify.py       Jinja2 rendering, SMTP / Graph mail, webhooks
  scheduler.py    daemon (APScheduler cron jobs + heartbeat)
  graph.py        Microsoft Graph client (MSAL client credentials)
  sources/        entra.py, sslcert.py (+ base.py for new sources)
  templates/      default email template
docs/expiry.1     man page
scripts/          host wrapper, Entra setup script
```

## License

[MIT](LICENSE): free to use, modify and distribute, including commercially, as long as the
copyright notice is kept. Provided as-is, without warranty.
