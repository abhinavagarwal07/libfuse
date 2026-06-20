#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
HELPER="$SCRIPT_DIR/safe_umount_proc_namespace"
HELPER_SRC="$SCRIPT_DIR/safe_umount_proc_namespace.c"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[skip] mount namespace proof requires Linux"
  exit 0
fi

if ! command -v unshare >/dev/null 2>&1; then
  echo "[fallback] unshare(1) is not available; using throwaway tmpfs unmount proof"
  bash "$SCRIPT_DIR/safe_tmpfs_unmount_demo.sh"
  exit 0
fi

echo "[build] compiling guarded umount2 helper"
cc -Wall -Wextra -O2 -o "$HELPER" "$HELPER_SRC"

PARENT_MNT_NS="$(readlink /proc/self/ns/mnt)"
echo "[parent] mount namespace: $PARENT_MNT_NS"
echo "[parent] /proc/self/status is readable before proof"
test -r /proc/self/status

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  RUN=(unshare --mount --fork --propagation private)
else
  RUN=(sudo -E unshare --mount --fork --propagation private)
fi

export POC_PARENT_MNT_NS="$PARENT_MNT_NS"
export POC_ALLOW_PROC_UMOUNT="mount-namespace-only"
export POC_HELPER="$HELPER"

if ! "${RUN[@]}" bash -euo pipefail -c '
  echo "[child] mount namespace: $(readlink /proc/self/ns/mnt)"
  echo "[child] launching three victim job loops in this namespace"

  victim() {
    local name="$1"
    while :; do
      if [[ -r /proc/self/status ]]; then
        echo "[victim-$name] /proc OK"
        sleep 1
      else
        echo "[victim-$name] /proc FAILED after umount2"
        exit 23
      fi
    done
  }

  victim A &
  pid_a=$!
  victim B &
  pid_b=$!
  victim C &
  pid_c=$!

  sleep 2
  "$POC_HELPER"

  wait "$pid_a" || true
  wait "$pid_b" || true
  wait "$pid_c" || true

  if [[ -r /proc/self/status ]]; then
    echo "[child] unexpected: /proc is still readable"
    exit 1
  fi

  echo "[child] confirmed: victim loops observed /proc loss in private namespace"
'; then
  echo "[fallback] private namespace /proc proof failed; using throwaway tmpfs unmount proof"
  bash "$SCRIPT_DIR/safe_tmpfs_unmount_demo.sh"
  exit 0
fi

echo "[parent] verifying parent namespace was not damaged"
test -r /proc/self/status
echo "[parent] /proc is still readable in the parent namespace"
