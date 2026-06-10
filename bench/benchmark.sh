#!/usr/bin/env bash
# =============================================================================
# benchmark.sh — M3 效能基準：量化 eBPF 探針帶來的 openat 延遲與 CPU 開銷
# 用法：
#   1) 不啟動 daemon 時跑一次（基準）：   ./bench/benchmark.sh baseline
#   2) 啟動 sentinel daemon 後量旁觀者成本：      ./bench/benchmark.sh withbpf
#   3) daemon 執行中，以 root 量受監控 PID 成本： sudo ./bench/benchmark.sh tracked
#   baseline → withbpf 是旁觀者成本；baseline → tracked 是受監控程序完整成本。
# =============================================================================
set -euo pipefail
LABEL="${1:-run}"
ITERS="${2:-200000}"
TMPF="$(mktemp /tmp/sentinel_bench.XXXXXX)"
echo "benign" > "$TMPF"

echo "[bench:$LABEL] openat x $ITERS on $TMPF"
python3 - "$TMPF" "$ITERS" "$LABEL" <<'PY'
import os, struct, subprocess, sys, time
path, iters, label = sys.argv[1], int(sys.argv[2]), sys.argv[3]
tracked = label == "tracked"
map_path = "/sys/fs/bpf/tracked_pids"

def bpftool_update(pid):
    key = struct.pack("<I", pid)
    cmd = ["bpftool", "map", "update", "pinned", map_path, "key", "hex"]
    cmd += ["%02x" % b for b in key]
    cmd += ["value", "hex", "01"]
    subprocess.run(cmd, check=True)

def bpftool_delete(pid):
    key = struct.pack("<I", pid)
    cmd = ["bpftool", "map", "delete", "pinned", map_path, "key", "hex"]
    cmd += ["%02x" % b for b in key]
    subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

if tracked:
    try:
        bpftool_update(os.getpid())
        print("[bench:%s] tracked pid=%d via %s" % (label, os.getpid(), map_path))
    except Exception as e:
        print("[bench:%s] failed to track self: %s" % (label, e), file=sys.stderr)
        sys.exit(2)

# 預熱
try:
    for _ in range(1000):
        fd = os.open(path, os.O_RDONLY); os.close(fd)
    t0 = time.perf_counter_ns()
    for _ in range(iters):
        fd = os.open(path, os.O_RDONLY); os.close(fd)
    t1 = time.perf_counter_ns()
finally:
    if tracked:
        bpftool_delete(os.getpid())
total_ns = t1 - t0
per = total_ns / iters
print("[bench:%s] total=%.1f ms  per_openat=%.0f ns (%.3f us)" %
      (label, total_ns/1e6, per, per/1000.0))
PY

rm -f "$TMPF"

cat <<'NOTE'

----------------------------------------------------------------------------
解讀：
  旁觀者探針開銷(ns/op) ≈ per_openat(withbpf) - per_openat(baseline)
  受監控程序完整開銷(ns/op) ≈ per_openat(tracked) - per_openat(baseline)
  tracked 模式需 daemon 已建立 /sys/fs/bpf/tracked_pids，且通常需 sudo。
CPU 開銷觀察（另開終端，daemon 執行中）：
  pidstat -p $(pgrep -f sentinel/main.py) 1
記憶體：
  grep VmRSS /proc/$(pgrep -f sentinel/main.py)/status
注意：在 VM 內量測會有虛擬化雜訊；報告用數據建議於雲端 ARM/裸機等級實例取得。
----------------------------------------------------------------------------
NOTE
