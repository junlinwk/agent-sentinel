#!/usr/bin/env python3
"""
main.py — agent-sentinel 監控+阻斷 daemon（編排器）。

流程：
  1. 載入 action_probes.c（行為擷取，建立 events + pinned tracked_pids）
  2. 載入 lsm_enforce.c（建立 pinned sensitive_inodes，掛載 LSM）
  3. enforcer 載入靜態敏感路徑（含 dev 換算）
  4. 啟動 intent 尾隨執行緒（讀 agent 寫的 intent.jsonl）
  5. （可選）啟動並納管受測代理 PID
  6. poll ring buffer：正規化 → 血統 → 關聯 → 視需要動態阻斷
須以 root 執行；kernel >= 5.7 且開機已啟用 lsm=...,bpf；bpffs 掛載於 /sys/fs/bpf。

用法：
  sudo python3 sentinel/main.py --config config.yaml \
       --launch "python3 agent/target_agent.py --task attacks/indirect_injection.md"
  # 或監控既有行程：
  sudo python3 sentinel/main.py --config config.yaml --track-pid 12345
"""
import argparse
import json
import os
import shlex
import signal
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import normalizer            # noqa: E402
from lineage import Lineage  # noqa: E402
from correlator import Correlator  # noqa: E402
from enforcer import Enforcer      # noqa: E402
import loader                 # noqa: E402

try:
    import yaml
except Exception:
    yaml = None


def load_config(path):
    if yaml is None:
        raise RuntimeError("缺少 pyyaml；pip install pyyaml")
    with open(path) as f:
        return yaml.safe_load(f)


class JsonlWriter:
    def __init__(self, path):
        self.path = path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        self._f = os.fdopen(fd, "w", buffering=1)  # line-buffered
        os.chmod(path, 0o600)

    def write(self, obj):
        self._f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    def close(self):
        try:
            self._f.close()
        except Exception:
            pass


def intent_tail(path, correlator, stop_evt):
    """尾隨 agent 寫入的 intent.jsonl，餵給關聯引擎。"""
    # 等待檔案出現
    while not stop_evt.is_set() and not os.path.exists(path):
        time.sleep(0.1)
    if stop_evt.is_set():
        return
    with open(path) as f:
        while not stop_evt.is_set():
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            correlator.add_intent(evt.get("ts_ns", 0),
                                  evt.get("text", ""),
                                  evt.get("role", "response"))


def truncate_private(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.close(fd)
    os.chmod(path, 0o600)


def self_test_lsm(enforcer, path):
    """Fail closed if a tracked PID can still open a preloaded sensitive path."""
    if not path:
        raise RuntimeError("LSM self-test requires at least one sensitive path")
    enforcer.track_pid(os.getpid())
    try:
        try:
            with open(path, "rb") as f:
                f.read(1)
        except PermissionError:
            print("[self-test] LSM blocked daemon self-test open: %s" % path)
            return
        raise RuntimeError("LSM self-test failed: tracked PID could open %s" % path)
    finally:
        enforcer.untrack_pid(os.getpid())


def wait_stopped(pid, timeout_s=3.0):
    deadline = time.monotonic() + timeout_s
    stat_path = "/proc/%d/stat" % pid
    while time.monotonic() < deadline:
        try:
            with open(stat_path) as f:
                fields = f.read().split()
            if len(fields) >= 3 and fields[2] in ("T", "t"):
                return True
        except OSError:
            return False
        time.sleep(0.01)
    return False


def has_path_evidence(alert):
    for intent in alert.get("matched_intents", []):
        for reason in intent.get("reasons", []):
            if reason.startswith("path-"):
                return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--launch", help="啟動並納管的代理指令（會自動 track 其 PID）")
    ap.add_argument("--track-pid", type=int, help="納管既有行程 PID")
    ap.add_argument("--duration", type=int, default=0, help="執行秒數（0=直到 Ctrl-C 或代理結束）")
    ap.add_argument("--keep-maps", action="store_true", help="啟動時不清除既有 pinned map")
    ap.add_argument("--skip-lsm-self-test", action="store_true",
                    help="略過啟動期 LSM 阻斷自測（不建議 demo/驗收使用）")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("[!] 需以 root 執行（載入 BPF/LSM）", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(args.config)
    pin_dir = cfg.get("pin_dir", "/sys/fs/bpf")
    bpf_dir = cfg.get("bpf_dir", "bpf")
    runtime_dir = cfg.get("runtime_dir", "/tmp/agent-sentinel")
    os.makedirs(runtime_dir, exist_ok=True)

    if not args.keep_maps:
        loader.cleanup_pins(pin_dir)
    loader.ensure_pinned_maps(pin_dir)

    # ---- 載入 BPF ----
    print("[*] 載入行為探針 action_probes.c ...")
    action = loader.ActionLoader(os.path.join(bpf_dir, "action_probes.c"))
    print("[*] 載入 LSM 探針 lsm_enforce.c ...")
    lsm = loader.LsmLoader(os.path.join(bpf_dir, "lsm_enforce.c"))

    enforcer = Enforcer(lsm.bpf, action.bpf)
    enforcer.load_static(cfg.get("sensitive_paths", []))
    if not args.skip_lsm_self_test:
        test_paths = [p for p in cfg.get("sensitive_paths", []) if os.path.exists(p)]
        self_test_lsm(enforcer, test_paths[0] if test_paths else None)

    lineage = Lineage()
    action_log = JsonlWriter(cfg["action_log_path"])
    alert_log = JsonlWriter(cfg["alert_log_path"])
    # 截斷 intent log，讓尾隨從乾淨狀態開始（agent 之後寫入）
    truncate_private(cfg["intent_log_path"])

    enable_dyn = bool(cfg.get("enable_dynamic_enforcement", True))

    def on_alert(alert):
        alert_log.write(alert)
        tag = alert["verdict"]
        print("[ALERT] %s pid=%d comm=%s path=%s score=%.2f intents=%d" % (
            tag, alert["pid"], alert["comm"], alert["path"],
            alert["intent_score"], len(alert["matched_intents"])))
        # 動態擴防：新發現的可疑目標加入黑名單（靜態已涵蓋者不重複）
        if (enable_dyn and alert["is_sensitive"] is False
                and tag != "SENSITIVE_ACCESS" and has_path_evidence(alert)):
            if enforcer.add_dynamic_path(alert["path"]):
                print("[enforce] 動態加入黑名單：%s" % alert["path"])

    correlator = Correlator(cfg.get("correlation_window_ms", 500),
                            cfg.get("intent_keywords", []),
                            lineage, on_alert=on_alert)

    stats = {"events": 0, "open": 0, "sensitive": 0}
    ignored_pids = {os.getpid()}

    def on_event(raw):
        evt = normalizer.normalize(raw)
        if evt["pid"] in ignored_pids:
            return
        stats["events"] += 1
        lineage.on_event(evt)
        action_log.write(evt)
        if evt["type"] == "open":
            stats["open"] += 1
            is_sens = enforcer.is_sensitive_path(evt["path"])
            if is_sens:
                stats["sensitive"] += 1
            correlator.on_action(evt, is_sens)

    action.set_callback(on_event)

    # ---- intent 尾隨執行緒 ----
    stop_evt = threading.Event()
    t = threading.Thread(target=intent_tail,
                         args=(cfg["intent_log_path"], correlator, stop_evt),
                         daemon=True)
    t.start()

    # ---- 納管代理 ----
    proc = None
    if args.track_pid:
        enforcer.track_pid(args.track_pid)
        lineage.set_root(args.track_pid)
    if args.launch:
        env = dict(os.environ)
        env["SENTINEL_INTENT_LOG"] = cfg["intent_log_path"]
        env["SENTINEL_CONFIG"] = os.path.abspath(args.config)
        env["PYTHONUNBUFFERED"] = "1"
        launch_argv = shlex.split(args.launch)
        wrapper = ["/bin/sh", "-c", 'kill -STOP $$; exec "$@"',
                   "agent-sentinel-launch"] + launch_argv
        proc = subprocess.Popen(wrapper, env=env)
        if not wait_stopped(proc.pid):
            proc.terminate()
            raise RuntimeError("agent wrapper did not stop before exec; refusing to launch untracked")
        enforcer.track_pid(proc.pid)
        lineage.set_root(proc.pid, comm="agent-root", ts=0)
        os.kill(proc.pid, signal.SIGCONT)
        print("[*] 已啟動並納管代理 PID=%d" % proc.pid)

    print("[*] sentinel 運行中（Ctrl-C 結束）。已追蹤 PID 數：%d" % enforcer.tracked_count())
    print("    驗證 LSM 阻斷：sudo cat /sys/kernel/debug/tracing/trace_pipe | grep 'BPF LSM'")

    # ---- 主迴圈 ----
    running = {"v": True}

    def _sig(_s, _f):
        running["v"] = False
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    start = time.monotonic()
    try:
        while running["v"]:
            action.poll(200)
            if proc is not None and proc.poll() is not None:
                # 代理結束，再排空一小段時間
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    action.poll(100)
                break
            if args.duration and (time.monotonic() - start) >= args.duration:
                break
    finally:
        stop_evt.set()
        print("\n[*] 結束。事件=%d open=%d 命中敏感=%d 追蹤PID=%d"
              % (stats["events"], stats["open"], stats["sensitive"], enforcer.tracked_count()))
        print("    行為日誌：%s" % cfg["action_log_path"])
        print("    告警日誌：%s" % cfg["alert_log_path"])
        action_log.close()
        alert_log.close()
        if not args.keep_maps:
            loader.cleanup_pins(pin_dir)


if __name__ == "__main__":
    main()
