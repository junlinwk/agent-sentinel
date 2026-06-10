"""
normalizer.py — 將核心 ring buffer 的原始事件正規化為統一 JSON 結構。

輸出 schema（每筆 dict）：
  {
    "ts_ns": int,            # CLOCK_MONOTONIC ns（與 agent intent 同時鐘）
    "type": "fork"|"exec"|"open",
    "pid": int, "ppid": int, "uid": int,
    "comm": str,
    "raw_path": str,         # 探針原始擷取（openat 可能是相對路徑）
    "path": str,             # 盡力還原後的絕對路徑
    "flags": int,            # open flags
    "flags_str": str         # 解碼後（如 "O_RDONLY|O_CLOEXEC"）
  }

注意：本模組不匯入 bcc，僅處理已解碼的欄位，便於離線測試與語法驗證。
"""
import os

EVT_FORK, EVT_EXEC, EVT_OPEN = 1, 2, 3
_TYPE_NAME = {EVT_FORK: "fork", EVT_EXEC: "exec", EVT_OPEN: "open"}

# open(2) flags（與 x86-64/arm64 一致的常見值；僅供人類可讀化）
_O_FLAGS = [
    (os.O_WRONLY, "O_WRONLY"),
    (os.O_RDWR, "O_RDWR"),
    (getattr(os, "O_CREAT", 0o100), "O_CREAT"),
    (getattr(os, "O_EXCL", 0o200), "O_EXCL"),
    (getattr(os, "O_TRUNC", 0o1000), "O_TRUNC"),
    (getattr(os, "O_APPEND", 0o2000), "O_APPEND"),
    (getattr(os, "O_NONBLOCK", 0o4000), "O_NONBLOCK"),
    (getattr(os, "O_DIRECTORY", 0o200000), "O_DIRECTORY"),
    (getattr(os, "O_CLOEXEC", 0o2000000), "O_CLOEXEC"),
]


def decode_flags(flags):
    """把 open flags 轉成人類可讀字串。O_RDONLY(0) 為預設。"""
    if flags is None:
        return ""
    parts = []
    # 存取模式（低 2 位）
    acc = flags & 0o3
    if acc == os.O_WRONLY:
        parts.append("O_WRONLY")
    elif acc == os.O_RDWR:
        parts.append("O_RDWR")
    else:
        parts.append("O_RDONLY")
    for bit, name in _O_FLAGS:
        if name in ("O_WRONLY", "O_RDWR"):
            continue
        if bit and (flags & bit):
            parts.append(name)
    return "|".join(parts)


def resolve_path(pid, raw_path):
    """
    盡力還原相對路徑（對應 IMPLEMENTATION checklist「相對路徑還原」）。
    絕對路徑直接回傳；相對路徑以 /proc/<pid>/cwd 為基準解析。
    為 best-effort：行程可能已結束或 cwd 已變動。LSM 阻斷以 inode 為準，
    不依賴此還原，故失敗不影響防禦正確性。
    """
    if not raw_path:
        return raw_path
    if raw_path.startswith("/"):
        return os.path.normpath(raw_path)
    try:
        cwd = os.readlink("/proc/%d/cwd" % pid)
        return os.path.normpath(os.path.join(cwd, raw_path))
    except OSError:
        return raw_path


def _cstr(raw):
    """把 ctypes char 陣列 / bytes 解成 str。"""
    if isinstance(raw, bytes):
        b = raw
    else:
        b = bytes(raw)
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


def normalize(event):
    """
    event：ring buffer 解碼出的 ctypes 結構（欄位見 bpf/action_probes.c::event_t）。
    回傳正規化 dict。
    """
    etype = int(event.type)
    pid = int(event.pid)
    raw_path = _cstr(event.path)
    out = {
        "ts_ns": int(event.timestamp),
        "type": _TYPE_NAME.get(etype, "unknown(%d)" % etype),
        "pid": pid,
        "ppid": int(event.ppid),
        "uid": int(event.uid),
        "comm": _cstr(event.comm),
        "raw_path": raw_path,
        "path": resolve_path(pid, raw_path) if etype == EVT_OPEN else raw_path,
        "flags": int(event.flags),
        "flags_str": decode_flags(int(event.flags)) if etype == EVT_OPEN else "",
    }
    return out
