"""
loader.py — 載入 BPF 探針並橋接 ring buffer。

ActionLoader：載入 bpf/action_probes.c（tracepoints 自動掛載），
              開啟 events ring buffer，把每筆事件解碼後交給 callback。
LsmLoader   ：載入 bpf/lsm_enforce.c（LSM_PROBE 於載入時自動掛載）。
IntentLoader：可選；載入 bpf/intent_probes.c 並以 uprobe 掛 libssl（進階/TLS 情境）。

需要 root，且 bpffs 需掛載於 /sys/fs/bpf。
"""
import os
import platform
import shutil
import subprocess
import tempfile

try:
    from bcc import BPF
except Exception:  # 本機未安裝 bcc 時，僅供語法檢查/離線測試
    BPF = None


def _require_bcc():
    if BPF is None:
        raise RuntimeError("bcc 未安裝；請在目標機執行 setup/00_setup_env.sh（python3-bpfcc）")


def ensure_pinned_maps(pin_dir="/sys/fs/bpf"):
    """Create shared pinned maps before BPF_TABLE_PINNED programs open them."""
    os.makedirs(pin_dir, exist_ok=True)
    maps = (
        ("tracked_pids", "hash", 4, 1, 10240),
        ("sensitive_inodes", "hash", 16, 1, 4096),
    )
    for name, map_type, key_size, value_size, entries in maps:
        path = os.path.join(pin_dir, name)
        if os.path.exists(path):
            continue
        subprocess.run(
            [
                "bpftool", "map", "create", path,
                "type", map_type,
                "key", str(key_size),
                "value", str(value_size),
                "entries", str(entries),
                "name", name,
            ],
            check=True,
        )


class ActionLoader:
    def __init__(self, src_path):
        _require_bcc()
        with open(src_path) as f:
            text = f.read()
        # tracepoints（tracepoint__... / 由 TRACEPOINT_PROBE 產生）於載入時自動掛載
        self.bpf = BPF(text=text)
        self._cb = None

    def tracked_pids(self):
        return self.bpf["tracked_pids"]

    def set_callback(self, cb):
        """cb(raw_event) 其中 raw_event 為 events ring buffer 的解碼結構。"""
        self._cb = cb

        def _raw(ctx, data, size):
            event = self.bpf["events"].event(data)
            self._cb(event)

        self.bpf["events"].open_ring_buffer(_raw)

    def poll(self, timeout_ms=200):
        self.bpf.ring_buffer_poll(timeout_ms)


class LsmLoader:
    def __init__(self, src_path):
        _require_bcc()
        pin_dir = os.path.dirname(os.path.realpath("/sys/fs/bpf/tracked_pids"))
        self._link_dir = os.path.join(pin_dir, "agent_sentinel_lsm")
        self._load_libbpf(src_path, pin_dir)
        self.bpf = BPF(text="""
#include <uapi/linux/ptrace.h>
struct file_key { u64 dev; u64 ino; };
BPF_TABLE_PINNED("hash", struct file_key, u8, sensitive_inodes, 4096, "/sys/fs/bpf/sensitive_inodes");
BPF_TABLE_PINNED("hash", u32, u8, tracked_pids, 10240, "/sys/fs/bpf/tracked_pids");
""")

    def _load_libbpf(self, src_path, pin_dir):
        src_dir = os.path.dirname(os.path.abspath(src_path))
        libbpf_src = os.path.join(src_dir, "lsm_enforce_libbpf.c")
        if not os.path.exists(libbpf_src):
            raise RuntimeError("missing libbpf LSM source: %s" % libbpf_src)

        cleanup_lsm_link(pin_dir)
        with tempfile.TemporaryDirectory(prefix="agent-sentinel-bpf-") as td:
            vmlinux_h = os.path.join(td, "vmlinux.h")
            obj = os.path.join(td, "lsm_enforce_libbpf.o")
            with open(vmlinux_h, "w") as out:
                subprocess.run(
                    ["bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"],
                    check=True,
                    stdout=out,
                )
            subprocess.run(
                [
                    "clang", "-O2", "-g", "-target", "bpf",
                    "-D__TARGET_ARCH_%s" % _target_arch(),
                    "-I", td,
                    "-I", _multiarch_include(),
                    "-c", libbpf_src,
                    "-o", obj,
                ],
                check=True,
            )
            subprocess.run(
                [
                    "bpftool", "prog", "loadall", obj, self._link_dir,
                    "map", "name", "tracked_pids", "pinned", os.path.join(pin_dir, "tracked_pids"),
                    "map", "name", "sensitive_inodes", "pinned", os.path.join(pin_dir, "sensitive_inodes"),
                    "autoattach",
                ],
                check=True,
            )
        print("[lsm] libbpf autoattach lsm/file_open 成功")

    def sensitive_inodes(self):
        return self.bpf["sensitive_inodes"]

    def tracked_pids(self):
        return self.bpf["tracked_pids"]


class IntentLoader:
    """可選：zero-instrumentation 意圖擷取（uprobe libssl）。僅在代理走 TLS 時適用。"""
    def __init__(self, src_path, libssl_path="/lib/x86_64-linux-gnu/libssl.so.3"):
        _require_bcc()
        with open(src_path) as f:
            text = f.read()
        self.bpf = BPF(text=text)
        self.libssl_path = libssl_path
        self._cb = None

    def attach(self):
        b, lib = self.bpf, self.libssl_path
        b.attach_uprobe(name=lib, sym="SSL_write", fn_name="uprobe_ssl_write")
        b.attach_uprobe(name=lib, sym="SSL_read", fn_name="uprobe_ssl_read_enter")
        b.attach_uretprobe(name=lib, sym="SSL_read", fn_name="uretprobe_ssl_read_return")

    def set_callback(self, cb):
        self._cb = cb

        def _raw(ctx, data, size):
            self._cb(self.bpf["ssl_events"].event(data))

        self.bpf["ssl_events"].open_ring_buffer(_raw)

    def poll(self, timeout_ms=200):
        self.bpf.ring_buffer_poll(timeout_ms)


def cleanup_lsm_link(pin_dir="/sys/fs/bpf"):
    path = os.path.join(pin_dir, "agent_sentinel_lsm")
    try:
        shutil.rmtree(path)
    except OSError:
        pass


def cleanup_pins(pin_dir="/sys/fs/bpf", names=("tracked_pids", "sensitive_inodes")):
    """移除殘留的 pinned map（避免上次執行的型別/內容干擾本次）。"""
    cleanup_lsm_link(pin_dir)
    for n in names:
        p = os.path.join(pin_dir, n)
        try:
            os.unlink(p)
        except OSError:
            pass


def _target_arch():
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return machine


def _multiarch_include():
    machine = platform.machine().lower()
    candidates = []
    if machine in ("x86_64", "amd64"):
        candidates.append("/usr/include/x86_64-linux-gnu")
    elif machine in ("aarch64", "arm64"):
        candidates.append("/usr/include/aarch64-linux-gnu")
    candidates.append("/usr/include")
    for path in candidates:
        if os.path.isdir(path):
            return path
    return "/usr/include"
