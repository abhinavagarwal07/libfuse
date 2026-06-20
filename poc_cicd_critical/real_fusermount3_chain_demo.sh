#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROBE="$SCRIPT_DIR/real_fusermount3_chain_probe"
PROBE_SRC="$SCRIPT_DIR/real_fusermount3_chain_probe.c"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[skip] real fusermount3 chain probe requires Linux"
  exit 0
fi

if ! command -v unshare >/dev/null 2>&1; then
  echo "[skip] unshare(1) is not available"
  exit 0
fi

if ! command -v fusermount3 >/dev/null 2>&1; then
  echo "[skip] fusermount3 is not available"
  exit 0
fi

if ! command -v setpriv >/dev/null 2>&1; then
  echo "[skip] setpriv(1) is not available"
  exit 0
fi

ORIGINAL_USER="${SUDO_USER:-$(id -un)}"
ORIGINAL_UID="$(id -u "$ORIGINAL_USER")"
ORIGINAL_GID="$(id -g "$ORIGINAL_USER")"
if [[ "$ORIGINAL_USER" == "root" ]]; then
  echo "[skip] need a non-root user to exercise setuid fusermount3"
  exit 0
fi

echo "[build] compiling real fusermount3 chain probe"
cc -Wall -Wextra -O2 -o "$PROBE" "$PROBE_SRC"

PARENT_MNT_NS="$(readlink /proc/self/ns/mnt)"
echo "[parent] mount namespace: $PARENT_MNT_NS"
echo "[parent] running probe as user: $ORIGINAL_USER"

export POC_PARENT_MNT_NS="$PARENT_MNT_NS"
export POC_ALLOW_REAL_FUSERMOUNT="mount-namespace-only"
export POC_ORIGINAL_USER="$ORIGINAL_USER"
export POC_ORIGINAL_UID="$ORIGINAL_UID"
export POC_ORIGINAL_GID="$ORIGINAL_GID"
export POC_PROBE="$PROBE"

sudo -E unshare --mount --fork --propagation private bash -euo pipefail -c '
  echo "[child-root] mount namespace: $(readlink /proc/self/ns/mnt)"
  echo "[child-root] preparing private /run/mount/utab to exercise add_mount()"
  mount -t tmpfs -o mode=755 tmpfs /run
  mkdir -p /run/mount
  : > /run/mount/utab
  chmod 644 /run/mount/utab
  exec setpriv --reuid "$POC_ORIGINAL_UID" --regid "$POC_ORIGINAL_GID" --clear-groups env \
    POC_PARENT_MNT_NS="$POC_PARENT_MNT_NS" \
    POC_ALLOW_REAL_FUSERMOUNT="$POC_ALLOW_REAL_FUSERMOUNT" \
    "$POC_PROBE"
'
