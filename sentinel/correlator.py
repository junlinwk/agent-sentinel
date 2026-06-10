"""
correlator.py — 因果關聯引擎（解決語義斷層）。

三重關聯（對應 Plan.md 第三層）：
  1) 血統關聯：行為事件的 pid 須屬於代理行程樹（核心 BPF 已先過濾；此處再以
     lineage 標註上溯鏈，供 forensics）。
  2) 時間鄰近：行為事件需落在某「意圖事件」之後的滑動時間窗內（預設 500ms）。
  3) 語意比對：意圖文字中出現的路徑/關鍵詞與行為的目標路徑相符。

時鐘：意圖與行為事件皆使用 CLOCK_MONOTONIC ns（agent 與 BPF 同時鐘），可直接比較。
"""
import re
import threading
from collections import deque

# 從意圖文字抽取「看起來像絕對路徑」的字串
_PATH_RE = re.compile(r"(/[A-Za-z0-9_./\-]+)")


class Correlator:
    def __init__(self, window_ms, keywords, lineage, on_alert=None):
        self.window_ns = int(window_ms) * 1_000_000
        self.keywords = [k.lower() for k in (keywords or [])]
        self.lineage = lineage
        self.on_alert = on_alert            # callback(alert_dict)
        self._lock = threading.Lock()
        # 近期意圖事件：deque[(ts_ns, text, role)]
        self._intents = deque(maxlen=512)
        # 近期行為事件：deque[(evt, is_sensitive)]，供 intent 較晚到時回掃重判。
        self._actions = deque(maxlen=512)
        self._best = {}

    # ---- 意圖流 ----
    def add_intent(self, ts_ns, text, role="response"):
        alerts = []
        with self._lock:
            self._intents.append((int(ts_ns), text or "", role))
            for evt, is_sensitive in list(self._actions):
                if evt["ts_ns"] < int(ts_ns) or evt["ts_ns"] - int(ts_ns) > self.window_ns:
                    continue
                alert = self._build_alert(evt, is_sensitive)
                if alert and self._should_emit(alert):
                    alerts.append(alert)
        for alert in alerts:
            self.on_alert(alert)

    def _extract_paths(self, text):
        return set(_PATH_RE.findall(text or ""))

    def _matching_intents(self, action_ts, action_path):
        """回傳時間窗內、與 action_path 語意相符的意圖列表。"""
        lo = action_ts - self.window_ns
        hits = []
        for ts, text, role in self._intents:
            if ts < lo or ts > action_ts:
                continue
            tl = text.lower()
            score = 0.0
            reasons = []
            # 路徑直接出現
            if action_path and action_path in text:
                score += 0.6
                reasons.append("path-in-intent")
            elif action_path:
                for p in self._extract_paths(text):
                    if p == action_path or action_path.endswith(p) or p.endswith(action_path):
                        score += 0.5
                        reasons.append("path-overlap:%s" % p)
                        break
            # 關鍵詞
            for kw in self.keywords:
                if kw in tl:
                    score += 0.3
                    reasons.append("kw:%s" % kw)
                    break
            if score > 0:
                hits.append({"ts_ns": ts, "role": role, "score": round(score, 2),
                             "reasons": reasons, "text": text[:400]})
        return hits

    def _has_path_evidence(self, intents):
        for intent in intents:
            for reason in intent.get("reasons", []):
                if reason.startswith("path-"):
                    return True
        return False

    def _build_alert(self, evt, is_sensitive):
        if evt["type"] != "open":
            return None
        path = evt["path"]
        intents = self._matching_intents(evt["ts_ns"], path)

        # 判定：命中敏感檔 + 有時間窗內相符意圖 → 高度可信的注入越權
        threat = bool(intents) and is_sensitive
        # 即使無相符意圖，命中敏感檔本身也記錄為可疑（LSM 仍會阻斷）
        if not intents and not is_sensitive:
            return None
        # 非敏感路徑只有 keyword 命中時噪音太高；必須有 path overlap 才報 suspicious。
        if not is_sensitive and not self._has_path_evidence(intents):
            return None

        total = round(sum(i["score"] for i in intents), 2)
        alert = {
            "ts_ns": evt["ts_ns"],
            "verdict": "INJECTION_PRIVILEGE_ESCALATION" if threat
                       else ("SENSITIVE_ACCESS" if is_sensitive else "SUSPICIOUS_INTENT"),
            "pid": evt["pid"],
            "comm": evt["comm"],
            "uid": evt["uid"],
            "path": path,
            "flags_str": evt["flags_str"],
            "is_sensitive": is_sensitive,
            "intent_score": total,
            "matched_intents": intents,
            "ancestry": self.lineage.ancestry(evt["pid"]) if self.lineage else [],
        }
        return alert

    def _should_emit(self, alert):
        key = (alert["ts_ns"], alert["pid"], alert["path"])
        rank = {"SUSPICIOUS_INTENT": 1, "SENSITIVE_ACCESS": 2,
                "INJECTION_PRIVILEGE_ESCALATION": 3}
        old = self._best.get(key, 0)
        new = rank.get(alert["verdict"], 0)
        if new > old:
            self._best[key] = new
            return True
        return False

    # ---- 行為流 ----
    def on_action(self, evt, is_sensitive):
        """
        評估一筆行為事件是否構成「提示詞注入引發的越權」。
        evt：normalizer 正規化後的 open 事件。
        is_sensitive：該路徑是否屬於敏感清單（由 enforcer 判定）。
        回傳 alert dict（若構成威脅）或 None。
        """
        with self._lock:
            if evt["type"] == "open":
                self._actions.append((evt, is_sensitive))
            alert = self._build_alert(evt, is_sensitive)
            emit = bool(alert and self._should_emit(alert))

        # 觸發 on_alert 的情況：
        #   - threat / 命中靜態敏感檔（記錄 + 確認阻斷）
        #   - 有相符惡意意圖但目標未在靜態黑名單（SUSPICIOUS_INTENT）→ 供動態擴防
        if emit and self.on_alert:
            self.on_alert(alert)
        return alert
