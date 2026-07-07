#!/usr/bin/env bash
set -euo pipefail

# Minimal demo wrapper: run pi inside a bubblewrap root backed by sandboxfs.
#
# sandboxfs is used here to make the agent's filesystem view and operations
# observable, not to provide a strong isolation boundary. The view starts from
# host / and only hides /home by default. The wrapped process inherits the
# caller's environment; this script only replaces PATH with a small system PATH
# so hidden home PATH entries are not accidentally re-exposed.

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
HOST_CWD=$(pwd -P)
HOST_HOME=${HOME:?HOME must be set}
SANDBOXED_PATH=${PI_SANDBOX_PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}

require_executable() {
    local name=$1
    if ! command -v -- "$name" >/dev/null 2>&1; then
        printf 'pi-sandbox: required command not found: %s\n' "$name" >&2
        exit 127
    fi
}

resolve_sandboxfs() {
    if [[ -n ${SANDBOXFS_BIN:-} ]]; then
        printf '%s\n' "$SANDBOXFS_BIN"
    elif [[ -x "$SCRIPT_DIR/../target/debug/sandboxfs" ]]; then
        printf '%s\n' "$SCRIPT_DIR/../target/debug/sandboxfs"
    elif [[ -x "$SCRIPT_DIR/../target/release/sandboxfs" ]]; then
        printf '%s\n' "$SCRIPT_DIR/../target/release/sandboxfs"
    elif command -v sandboxfs >/dev/null 2>&1; then
        command -v sandboxfs
    else
        printf 'pi-sandbox: sandboxfs not found. Build it first or set SANDBOXFS_BIN.\n' >&2
        exit 127
    fi
}

resolve_pi() {
    if [[ -n ${PI_BIN:-} ]]; then
        printf '%s\n' "$PI_BIN"
    elif [[ -e /bin/pi ]]; then
        printf '/bin/pi\n'
    elif [[ -e /usr/bin/pi ]]; then
        printf '/usr/bin/pi\n'
    elif command -v pi >/dev/null 2>&1; then
        command -v pi
    else
        printf 'pi-sandbox: pi not found. Set PI_BIN or install pi.\n' >&2
        exit 127
    fi
}

BWRAP_BIN=${BWRAP_BIN:-bwrap}
require_executable "$BWRAP_BIN"
SANDBOXFS_BIN=$(resolve_sandboxfs)
PI_BIN=$(resolve_pi)

TMP_ROOT=$(mktemp -d -p /tmp pi-sandbox.XXXXXXXXXX)
RUNTIME_DIR=$TMP_ROOT/run
LOG_DIR=$TMP_ROOT/logs
ATTACH_DIR=$TMP_ROOT/root
SESSION_NAME=pi-sandbox-$$
SESSION_PID=

mkdir -p -- "$RUNTIME_DIR" "$LOG_DIR" "$ATTACH_DIR"

sf() {
    SANDBOXFS_RUNTIME_DIR=$RUNTIME_DIR \
    SANDBOXFS_LOG_DIR=$LOG_DIR \
        "$SANDBOXFS_BIN" "$SESSION_NAME" "$@"
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n ${SESSION_PID:-} ]]; then
        sf destroy >/dev/null 2>&1 || true
        wait "$SESSION_PID" 2>/dev/null || true
    fi
    if [[ ${PI_SANDBOX_KEEP:-0} == 1 ]]; then
        printf 'pi-sandbox: kept temporary directory: %s\n' "$TMP_ROOT" >&2
    else
        rm -rf -- "$TMP_ROOT"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

SANDBOXFS_RUNTIME_DIR=$RUNTIME_DIR \
SANDBOXFS_LOG_DIR=$LOG_DIR \
    "$SANDBOXFS_BIN" run "$SESSION_NAME" \
    >"$TMP_ROOT/sandboxfs-run.stdout" \
    2>"$TMP_ROOT/sandboxfs-run.stderr" &
SESSION_PID=$!

SOCKET=$RUNTIME_DIR/$SESSION_NAME.sock
for _ in {1..100}; do
    if [[ -S $SOCKET ]]; then
        break
    fi
    if ! kill -0 "$SESSION_PID" 2>/dev/null; then
        printf 'pi-sandbox: sandboxfs run exited early\n' >&2
        sed -n '1,120p' "$TMP_ROOT/sandboxfs-run.stderr" >&2 || true
        exit 1
    fi
    sleep 0.05
done
if [[ ! -S $SOCKET ]]; then
    printf 'pi-sandbox: timed out waiting for sandboxfs socket: %s\n' "$SOCKET" >&2
    sed -n '1,120p' "$TMP_ROOT/sandboxfs-run.stderr" >&2 || true
    exit 1
fi

# Base view: root redirect for observability, with only /home hidden by default.
sf mount / /
sf hide /home

# If the caller's pi config lives under hidden /home, re-expose only that config
# directory so pi can run while other /home details remain hidden.
PI_HOME_DIR=$HOST_HOME/.pi
if [[ $PI_HOME_DIR == /home/* && -d $PI_HOME_DIR ]]; then
    sf mount "$PI_HOME_DIR" "$PI_HOME_DIR"
elif [[ $PI_HOME_DIR == /home/* ]]; then
    printf 'pi-sandbox: warning: %s does not exist; pi config may be unavailable\n' "$PI_HOME_DIR" >&2
fi

sf attach "$ATTACH_DIR"

cat >&2 <<EOF
pi-sandbox: sandboxfs session is running
  session: $SESSION_NAME
  runtime: $RUNTIME_DIR
  logs:    $LOG_DIR
  mount:   $ATTACH_DIR

Inspect the sandboxfs session from another terminal with:
  SANDBOXFS_RUNTIME_DIR=$RUNTIME_DIR SANDBOXFS_LOG_DIR=$LOG_DIR sandboxfs-access-tui $SESSION_NAME

Set PI_SANDBOX_KEEP=1 to keep the temporary directory after exit.
EOF

"$BWRAP_BIN" \
    --die-with-parent \
    --bind "$ATTACH_DIR" / \
    --dev /dev \
    --proc /proc \
    --chdir "$HOST_CWD" \
    --setenv PATH "$SANDBOXED_PATH" \
    "$PI_BIN" "$@"
