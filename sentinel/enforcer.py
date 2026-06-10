"""
enforcer.py — M2b 使用者空間阻斷控制。

職責：
  - 將靜態敏感路徑載入 sensitive_inodes（含 P2 的 dev 編碼換算）。
  - 提供動態加入（關聯引擎判威脅時）與 PID 納管的 API。
  - 兩張 map 皆為 pinned，與 BPF 物件共用；本類別只需任一持有該 map 的 BPF handle。

關鍵正確性（對應 P2）：
  核心 i_sb->s_dev 的 dev_t = (major << 20) | minor（MINORBITS=20），
  與 glibc os.stat().st_dev 的位元佈局不同；必須換算後才能與核心鍵相符，
  否則 sensitive_inodes 永遠查不到 → LSM 靜默放行。
"""
import os

MINORBITS = 20


def kernel_dev(st_dev):
    """glibc st_dev → 核心 dev_t 編碼 (major<<20)|minor。"""
    return (os.major(st_dev) << MINORBITS) | os.minor(st_dev)


class Enforcer:
    def __init__(self, lsm_bpf, action_bpf, logger=print):
        # sensitive_inodes 由 lsm_enforce.c 宣告；tracked_pids 兩者皆宣告（pinned 同一份）
        self._sens = lsm_bpf["sensitive_inodes"]
        self._tracked = action_bpf["tracked_pids"]
        self._log = logger
        self._loaded = {}   # (dev, ino) -> path（人類可讀記錄）

    # ---- 敏感 inode ----
    def _add_inode(self, dev, ino, path, dynamic=False):
        key = self._sens.Key(dev, ino)         # struct file_key {u64 dev; u64 ino}
        self._sens[key] = self._sens.Leaf(1)   # presence-based
        self._loaded[(dev, ino)] = path
        self._log("[enforce] %s block (dev=%d ino=%d) %s" %
                  ("DYN" if dynamic else "static", dev, ino, path))

    def load_static(self, paths):
        n = 0
        for p in paths:
            try:
                st = os.stat(p)
            except OSError as e:
                self._log("[enforce] skip %s (%s)" % (p, e.strerror))
                continue
            self._add_inode(kernel_dev(st.st_dev), st.st_ino, p)
            n += 1
        self._log("[enforce] static blacklist loaded: %d entr%s" % (n, "y" if n == 1 else "ies"))
        return n

    def add_dynamic_path(self, path):
        try:
            st = os.stat(path)
        except OSError:
            return False
        self._add_inode(kernel_dev(st.st_dev), st.st_ino, path, dynamic=True)
        return True

    def is_sensitive_path(self, path):
        """供關聯引擎判斷某路徑是否在黑名單（以 dev,ino 比對，對符號連結免疫）。"""
        try:
            st = os.stat(path)
        except OSError:
            return False
        return (kernel_dev(st.st_dev), st.st_ino) in self._loaded

    # ---- 行程納管 ----
    def track_pid(self, pid):
        key = self._tracked.Key(int(pid))
        self._tracked[key] = self._tracked.Leaf(1)
        self._log("[enforce] track pid %d" % pid)

    def untrack_pid(self, pid):
        key = self._tracked.Key(int(pid))
        try:
            del self._tracked[key]
            self._log("[enforce] untrack pid %d" % pid)
        except KeyError:
            pass

    def tracked_count(self):
        return sum(1 for _ in self._tracked.items())
