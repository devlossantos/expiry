#!/bin/sh
# Create the Entra ID app registration that expiry uses to read app secret/certificate
# expiry dates (Microsoft Graph Application.Read.All, application permission).
#
# Requirements: Azure CLI (az) logged in as a Global Administrator or
# Privileged Role Administrator (needed to grant admin consent):  az login --allow-no-subscriptions
#
# Usage:
#   sh scripts/entra-setup.sh                    # read-only access to app registrations
#   sh scripts/entra-setup.sh --mail             # + Mail.Send (email.transport: graph) - TENANT-WIDE:
#                                                #   for production scope it to one mailbox instead,
#                                                #   see README "Send email through Microsoft 365" option B
#   sh scripts/entra-setup.sh --owners           # + User.ReadBasic.All (sources.entra.notify_owners)
#   APP_NAME=my-expiry sh scripts/entra-setup.sh
set -eu

APP_NAME="${APP_NAME:-expiry-monitor}"
GRAPH=00000003-0000-0000-c000-000000000000
APPLICATION_READ_ALL=9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30
MAIL_SEND=b633e1c5-b582-4048-a93e-9f11b44c7e96
USER_READBASIC_ALL=97235f07-e226-4f63-ace3-39588e11d3a1

PERMS="$APPLICATION_READ_ALL=Role"
for arg in "$@"; do
    case "$arg" in
        --mail)   PERMS="$PERMS $MAIL_SEND=Role" ;;
        --owners) PERMS="$PERMS $USER_READBASIC_ALL=Role" ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

command -v az >/dev/null || { echo "Azure CLI (az) is required: https://aka.ms/azcli" >&2; exit 1; }
TENANT_ID=$(az account show --query tenantId -o tsv)

echo "Creating app registration '$APP_NAME' in tenant $TENANT_ID ..."
APP_ID=$(az ad app create --display-name "$APP_NAME" --sign-in-audience AzureADMyOrg --query appId -o tsv)
az ad sp create --id "$APP_ID" >/dev/null 2>&1 || true   # service principal (may already exist)

echo "Adding Microsoft Graph application permissions ..."
# shellcheck disable=SC2086
az ad app permission add --id "$APP_ID" --api "$GRAPH" --api-permissions $PERMS >/dev/null 2>&1

echo "Granting admin consent (waiting for the service principal to replicate) ..."
i=0
until az ad app permission admin-consent --id "$APP_ID" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -ge 12 ] && { echo "admin consent failed; grant it in the portal (API permissions -> Grant admin consent)" >&2; break; }
    sleep 10
done

echo "Creating a client secret (valid 12 months - expiry will remind you before it expires) ..."
SECRET=$(az ad app credential reset --id "$APP_ID" --display-name "expiry" --years 1 --append --query password -o tsv)

cat <<EOF

Done. Put these values in /etc/expiry/expiry.env:

ENTRA_TENANT_ID=$TENANT_ID
ENTRA_CLIENT_ID=$APP_ID
ENTRA_CLIENT_SECRET=$SECRET

Then set sources.entra.enabled: true in /etc/expiry/config.yaml, restart the container
(docker restart expiry) and verify with:  expiry config check --connect && expiry sync
EOF
