#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[skip] tmpfs unmount proof requires Linux"
  exit 0
fi

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  SUDO=()
else
  SUDO=(sudo)
fi

mnt="$(mktemp -d /tmp/poc-cicd-safe-umount.XXXXXX)"

cleanup() {
  if mountpoint -q "$mnt" 2>/dev/null; then
    "${SUDO[@]}" umount "$mnt" 2>/dev/null || true
  fi
  rmdir "$mnt" 2>/dev/null || true
}
trap cleanup EXIT

echo "[tmpfs] mounting throwaway tmpfs at $mnt"
"${SUDO[@]}" mount -t tmpfs -o size=1m,mode=700 poc_cicd_safe_umount "$mnt"

if ! mountpoint -q "$mnt"; then
  echo "[tmpfs] mount did not appear"
  exit 1
fi

echo "proof" > "$mnt/proof.txt"
echo "[tmpfs] mounted and wrote proof file"

echo "[tmpfs] performing real unmount of $mnt"
"${SUDO[@]}" umount "$mnt"

if mountpoint -q "$mnt"; then
  echo "[tmpfs] unmount failed"
  exit 1
fi

echo "[tmpfs] real unmount completed; mountpoint is detached"
