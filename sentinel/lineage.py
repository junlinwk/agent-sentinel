"""
lineage.py — 使用者空間的行程血統樹（forensics / 關聯輔助）。

注意：真正用於 LSM 判定的 tracked_pids 集合是在「核心態」由 fork 探針維護
（見 bpf/action_probes.c，對應 P7），本模組僅維護一份「人類可讀」的血統樹副本，
供日誌與關聯引擎標註用途，不參與阻斷決策。
"""
import threading


class Lineage:
    def __init__(self, root_pid=None, root_comm="agent-root"):
        self._lock = threading.Lock()
        # pid -> {ppid, comm, start_ts}
        self._tree = {}
        self.root_pid = root_pid
        if root_pid is not None:
            self._tree[root_pid] = {"ppid": 0, "comm": root_comm, "start_ts": 0}

    def set_root(self, pid, comm="agent-root", ts=0):
        with self._lock:
            self.root_pid = pid
            self._tree[pid] = {"ppid": 0, "comm": comm, "start_ts": ts}

    def on_event(self, evt):
        """以正規化事件更新血統樹。"""
        with self._lock:
            if evt["type"] == "fork":
                self._tree[evt["pid"]] = {
                    "ppid": evt["ppid"],
                    "comm": evt["comm"],
                    "start_ts": evt["ts_ns"],
                }
            elif evt["type"] in ("exec", "open"):
                node = self._tree.setdefault(
                    evt["pid"], {"ppid": 0, "comm": evt["comm"], "start_ts": evt["ts_ns"]}
                )
                if evt["type"] == "exec":
                    node["comm"] = evt["comm"]

    def is_descendant(self, pid):
        """pid 是否屬於代理行程樹（root 自身或其子孫）。"""
        with self._lock:
            seen = 0
            cur = pid
            while cur and cur in self._tree and seen < 64:
                if cur == self.root_pid:
                    return True
                cur = self._tree[cur]["ppid"]
                seen += 1
            return pid == self.root_pid

    def ancestry(self, pid):
        """回傳由 pid 上溯到 root 的 (pid, comm) 串列，供 forensics。"""
        with self._lock:
            chain = []
            cur = pid
            seen = 0
            while cur and cur in self._tree and seen < 64:
                chain.append((cur, self._tree[cur]["comm"]))
                if cur == self.root_pid:
                    break
                cur = self._tree[cur]["ppid"]
                seen += 1
            return chain

    def snapshot(self):
        with self._lock:
            return dict(self._tree)
