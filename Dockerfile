# syntax=docker/dockerfile:1
# ---------------------------------------------------------------- build
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

# ---------------------------------------------------------------- runtime
FROM python:3.12-slim

# org.opencontainers.image.source (the link to the GitHub repo) is added by the CI workflow.
LABEL org.opencontainers.image.title="expiry" \
      org.opencontainers.image.description="Expiry reminders for Entra ID app secrets/certificates, SSL certificates and anything else" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    EXPIRY_CONFIG=/config/config.yaml \
    EXPIRY_DB=/data/expiry.db \
    EXPIRY_SHARE_DIR=/opt/expiry/share \
    TZ=UTC

# - apply the latest Debian security updates at build time (the base tag can lag behind)
# - install the app, then remove pip: it is not needed at runtime (smaller attack surface)
# - run as an unprivileged user; /data (database) and /backups (optional backup mount) belong to it
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    apt-get update \
 && apt-get -y upgrade \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir /wheels/*.whl \
 && pip uninstall -y pip \
 && groupadd -g 10001 expiry \
 && useradd -u 10001 -g expiry -d /data -s /usr/sbin/nologin expiry \
 && mkdir -p /data /backups /config /opt/expiry/share/templates \
 && chown expiry:expiry /data /backups

COPY docs/expiry.1 config/config.example.yaml config/expiry.env.example scripts/expiry-host.sh /opt/expiry/share/
COPY src/expiry/templates/default.html.j2 /opt/expiry/share/templates/reminder.html.j2

USER expiry
WORKDIR /data
VOLUME ["/data"]

HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 CMD ["expiry", "health"]

ENTRYPOINT ["expiry"]
CMD ["daemon"]
