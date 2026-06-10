#!/usr/bin/env bash
# Final end-to-end verification for agent-sentinel.
set -euo pipefail

cd "$(dirname "$0")"

hr() { printf '%s\n' "----------------------------------------------------------------------"; }
section() { hr; printf '== %s ==\n' "$*"; }

section "privilege check"
id
grep '^NoNewPrivs:' /proc/self/status || true

if [ "$(id -u)" -ne 0 ]; then
  echo "[*] not root; checking sudo and re-executing as root..."
  sudo -n true
  exec sudo -E bash "$0" "$@"
fi

section "sudo/root file sanity"
ls -ln /etc/sudo.conf /etc/sudoers
if [ "$(stat -c '%u:%g' /etc/sudo.conf)" != "0:0" ]; then
  echo "[x] /etc/sudo.conf is not root:root" >&2
  exit 1
fi
if [ "$(stat -c '%u:%g' /etc/sudoers)" != "0:0" ]; then
  echo "[x] /etc/sudoers is not root:root" >&2
  exit 1
fi

section "kernel/eBPF preflight"
grep -qw bpf /sys/kernel/security/lsm
test -f /sys/kernel/btf/vmlinux
mount | grep -q 'bpf on /sys/fs/bpf'
echo "[ok] BPF LSM, BTF, and bpffs present"

section "offline tests"
PYTHONPYCACHEPREFIX=/tmp/agent-sentinel-pycache \
  python3 -m unittest discover -s tests -v
PYTHONPYCACHEPREFIX=/tmp/agent-sentinel-pycache \
  python3 -m py_compile sentinel/*.py agent/*.py tests/*.py
bash -n run_demo.sh bench/benchmark.sh tests/bypass_cases.sh setup/00_setup_env.sh \
  setup/oci-cloud-init.sh

section "attack demo"
timeout 180 bash ./run_demo.sh

section "benign demo"
timeout 180 bash ./run_demo.sh --benign

section "bypass cases"
timeout 360 ./tests/bypass_cases.sh

section "benchmarks"
./bench/benchmark.sh baseline
echo "[*] starting daemon for withbpf/tracked benchmark..."
timeout 150 python3 -u sentinel/main.py --config config.yaml --duration 120 \
  > /tmp/agent-sentinel-final-bench-daemon.log 2>&1 &
DAEMON_PID=$!
cleanup_daemon() {
  if kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
}
trap cleanup_daemon EXIT

for _ in $(seq 1 60); do
  if [ -e /sys/fs/bpf/tracked_pids ]; then
    break
  fi
  if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "[x] benchmark daemon exited early" >&2
    cat /tmp/agent-sentinel-final-bench-daemon.log >&2 || true
    exit 1
  fi
  sleep 1
done

if [ ! -e /sys/fs/bpf/tracked_pids ]; then
  echo "[x] /sys/fs/bpf/tracked_pids did not appear" >&2
  cat /tmp/agent-sentinel-final-bench-daemon.log >&2 || true
  exit 1
fi

./bench/benchmark.sh withbpf
./bench/benchmark.sh tracked
cleanup_daemon
trap - EXIT

section "log permissions"
stat -c '%a %n' /tmp/agent-sentinel/actions.jsonl \
  /tmp/agent-sentinel/alerts.jsonl /tmp/agent-sentinel/intent.jsonl

section "process cleanup check"
if ps -eo pid,ppid,stat,cmd | grep -E 'sentinel/main.py|target_agent.py|run_demo' | grep -v grep; then
  echo "[x] leftover agent/sentinel/demo processes found" >&2
  exit 1
fi

hr
echo "[done] final verification completed"
