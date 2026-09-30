#!/bin/sh
# expiry - host wrapper installed as /usr/local/bin/expiry.
# Forwards every command to the CLI inside the running "expiry" container, so users
# who SSH into the server can simply type: expiry list / expiry add ... / expiry rm ...
#
# Environment:
#   EXPIRY_CONTAINER  container name (default: expiry)
#   EXPIRY_DOCKER     docker binary  (default: docker; e.g. "sudo docker" or podman)

CONTAINER="${EXPIRY_CONTAINER:-expiry}"
DOCKER="${EXPIRY_DOCKER:-docker}"

state=$($DOCKER inspect -f '{{.State.Running}}' "$CONTAINER" 2>&1)
if [ "$state" != "true" ]; then
    case "$state" in
        *"permission denied"*)
            # No direct Docker access: if a sudo rule allows this wrapper without a password
            # (see README "Who can use the expiry command"), re-run through sudo automatically.
            # Uses the full path because RHEL-family sudo does not search /usr/local/bin.
            self=$(command -v "$0" 2>/dev/null || echo "$0")
            if [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1 && sudo -n -l "$self" >/dev/null 2>&1; then
                exec sudo -n "$self" "$@"
            fi
            echo "expiry: no permission to use Docker. Ask an admin to add you to the 'docker' group" >&2
            echo "        or to the 'expiry-users' sudo rule (see: man expiry), or run: sudo $self $*" >&2 ;;
        *"No such"*|*"no such"*)
            echo "expiry: container '$CONTAINER' does not exist. Start the service first (see: man expiry)." >&2 ;;
        false)
            echo "expiry: container '$CONTAINER' is stopped. Start it with: docker start $CONTAINER" >&2 ;;
        *)
            echo "expiry: cannot reach container '$CONTAINER': $state" >&2 ;;
    esac
    exit 1
fi

FLAGS="-i"
if [ -t 0 ] && [ -t 1 ]; then
    FLAGS="-it"
fi
ACTOR="${SUDO_USER:-$(id -un)}"
COLS=$(tput cols 2>/dev/null || echo 120)

exec $DOCKER exec $FLAGS -e EXPIRY_ACTOR="$ACTOR" -e COLUMNS="$COLS" "$CONTAINER" expiry "$@"
