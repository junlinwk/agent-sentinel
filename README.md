# agent-sentinel

> 基於 **eBPF + BPF LSM** 的本地 AI 代理行為安全稽核與**原子性阻斷**系統（PoC）。
> Cryptography Engineering — Final Project。

在**核心邊界**擷取本地 AI 代理（Ollama + Llama 3）的檔案/行程行為，在**應用邊界**擷取其
LLM 意圖，透過因果關聯還原「**提示詞注入 → 越權存取**」的攻擊鏈，並以 BPF LSM 在 VFS
底層**原子性阻斷**對 `/etc/shadow` 等敏感檔的存取（回 `-EPERM`），且**只對被納管的 AI
代理行程樹生效**，不影響 `login`/`sudo`/`cron` 等系統行程。

```
        意圖邊界（應用層）                    核心邊界（eBPF）
   ┌───────────────┐               ┌──────────────────────────┐
   │ target_agent  │  intent.jsonl │ action_probes.c          │
   │ (Ollama / L3) │──────────────▶│ fork/exec/openat/openat2 │──ringbuf─┐
   │  ReAct loop   │CLOCK_MONOTONIC│ + tracked_pids(核心態傳播）│          │
   └───────────────┘               └──────────────────────────┘          ▼
                                   ┌──────────────────────────┐   ┌────────────────┐
                                   │ lsm_enforce_libbpf.c     │   │ main.py daemon │
                                   │ lsm/file_open → -EPERM   │◀──│ normalizer     │
                                   │ sensitive_inodes(dev,ino)│   │ lineage        │
                                   └──────────────────────────┘   │ correlator     │
                                                                  │ enforcer       │
                                                                  └────────────────┘
```

兩個邊界各自不可信，**在 userspace 做三重關聯（血統 + 時間窗 + 語意）才補上 semantic gap**；
而阻斷與否完全由核心側的 `(dev, ino)` 決定，**不依賴 userspace 的關聯結果或路徑字串**——
即使關聯誤判或路徑還原失敗，敏感檔仍被擋（symlink/hardlink 繞過亦無效，見 `tests/bypass_cases.sh`）。

---

## 檔案結構

| 路徑 | 角色 |
|---|---|
| `bpf/action_probes.c` | fork/exec/openat/openat2 行為擷取 + **核心態 PID 傳播**（BCC） |
| `bpf/lsm_enforce_libbpf.c` | **目前實際載入**的 `lsm/file_open` 阻斷（libbpf/bpftool autoattach） |
| `bpf/lsm_enforce.c` | BCC 版 LSM 阻斷，保留作參考 |
| `bpf/intent_probes.c` | 【可選】SSL uprobe 零侵入意圖擷取（TLS 情境） |
| `sentinel/loader.py` | 載入 BPF、橋接 ring buffer、LSM 掛載、pinned map 建立 |
| `sentinel/normalizer.py` | 事件正規化、open flags 解碼、相對路徑 best-effort 還原 |
| `sentinel/lineage.py` | 行程血統樹（forensics） |
| `sentinel/correlator.py` | 三重關聯（血統 / 時間窗 / 語意比對） |
| `sentinel/enforcer.py` | 靜態/動態黑名單、**dev 換算**、PID 納管 |
| `sentinel/main.py` | daemon 編排器（per-event pipeline） |
| `agent/target_agent.py` | 受測代理（ReAct 迴圈 + 寫 `intent.jsonl`） |
| `agent/tools.py` | `read_file` / `run_shell` 工具（含敏感內容遮蔽） |
| `attacks/*.md` | baseline 正常任務 + 間接注入 payload（demo 輸入） |
| `tests/test_offline.py` | 離線單元測試（無需核心/root） |
| `tests/bypass_cases.sh` | symlink/hardlink inode-bypass 回歸（需 live LSM） |
| `bench/benchmark.sh` | openat 延遲 / CPU 基準 |
| `setup/00_setup_env.sh` | 互動環境建置（工具鏈/BTF/lsm 引導/Ollama，不自動改 GRUB） |
| `setup/oci-cloud-init.sh` | OCI 自動化建置（會改 GRUB 並 reboot 一次） |
| `config.yaml` | **單一事實來源**：敏感路徑、時間窗、關鍵詞、log 路徑、模型 |
| `run_demo.sh` | 一鍵 demo / DAC 排除證明 / PASS-FAIL 彙整 |
| `final_verify.sh` | 完整端到端 gate：tests + 雙情境 demo + bypass + 基準 + 清理 |

---

## 核心設計

### 1. 兩個邊界，一個 daemon
- **意圖邊界**：`target_agent.py` 用 **ReAct 文字協定**（`ACTION: tool(arg)` / `FINAL: ...`，regex 解析，
  刻意不用原生 function-calling，因 `llama3:8b` 工具使用不穩），每步把意圖以 `CLOCK_MONOTONIC` ns
  時戳寫入 `intent.jsonl`。
- **核心邊界**：`action_probes.c` 以 tracepoint 擷取 fork/exec/openat/openat2，經 ring buffer 上送 daemon。
- `main.py` 的 `on_event` pipeline：`normalizer.normalize` →（解碼結構/flags、best-effort 路徑還原）
  → `lineage.on_event`（血統樹）→ `correlator.on_action`（三重關聯）→ 發 alert → `enforcer.add_dynamic_path`
  可在執行期動態擴充黑名單。意圖事件由獨立 tail thread 讀入；**晚到的意圖會回掃、把
  `SENSITIVE_ACCESS` 升級為 `INJECTION_PRIVILEGE_ESCALATION`**。

### 2. 三重關聯（`correlator.py`）
一筆 open 行為要與某筆意圖配對，需同時滿足：
1. **血統**：行為的 pid 屬於代理行程樹（核心 BPF 已先過濾；userspace 再以 lineage 標註上溯鏈）。
2. **時間鄰近**：行為落在意圖之後的滑動時間窗內（`correlation_window_ms`，預設 500ms = 5×10⁸ ns；
   兩邊同用 `CLOCK_MONOTONIC` 故可直接比 ns）。
3. **語意比對**（量化評分，供判級與 forensics）：
   - 行為的完整目標路徑**原樣出現**在意圖文字 → **+0.6**（`path-in-intent`）。
   - 否則正則 `(/[A-Za-z0-9_./\-]+)` 從意圖抽出路徑，與目標有後綴關係 → **+0.5**（`path-overlap`，與 +0.6 互斥）。
   - 意圖含任一 `config.yaml::intent_keywords` 關鍵詞 → **+0.3**（只計一次）。

   判級：命中敏感檔 + 窗內有相符意圖 → `INJECTION_PRIVILEGE_ESCALATION`；只命中敏感檔 → `SENSITIVE_ACCESS`；
   非敏感路徑**必須有 path 證據**（光關鍵詞太吵會被濾掉）才報 `SUSPICIOUS_INTENT`。

### 3. 阻斷以 inode 為準（`lsm_enforce_libbpf.c` + `enforcer.py`）
- LSM `lsm/file_open` 對「pid ∈ `tracked_pids`」且「`(dev,ino)` ∈ `sensitive_inodes`」者回 `-EPERM`。
- 以 inode 為鍵 → **TOCTOU 免疫**、symlink/hardlink 繞過無效。
- `tracked_pids` / `sensitive_inodes` 是 pinned 在 `/sys/fs/bpf` 的共用 map；`action_probes.c`、
  `lsm_enforce_libbpf.c`、`loader.ensure_pinned_maps` 三處的 map 名稱/型別/key-value size **必須完全一致**。

---

## 前置需求（目標機）

- Ubuntu 22.04（核心 5.15+），x86-64 或 ARM64；**root**。
- `CONFIG_BPF_LSM=y` 且**開機參數已含 `lsm=...,bpf`**（否則 LSM 阻斷無法掛載）。
- BTF：`/sys/kernel/btf/vmlinux` 存在；bpffs 掛載於 `/sys/fs/bpf`。
- **BCC 來自 apt（`python3-bpfcc`），非 pip**；`requirements.txt` 只涵蓋 pip 依賴（`ollama`, `PyYAML`）。
- Ollama + `llama3:8b`。

> **本專案無 build step。** userspace 是純 Python；BPF C 在目標機載入時即時編譯（BCC 編 `action_probes.c`，
> clang 編 libbpf LSM）。**無法在一般機器上編譯/執行**，BPF 變更一律「上 cloud 實測」。

---

## 安裝

```bash
bash setup/00_setup_env.sh
# 若提示 "bpf 不在 LSM 清單"，依指示編輯 /etc/default/grub 加 lsm=...,bpf，update-grub，reboot
```

## 離線檢驗（任何機器、不需核心/root/BPF）

```bash
python3 -m unittest discover -s tests -v          # 離線單元測試
python3 -m py_compile sentinel/*.py agent/*.py     # Python 語法檢查
bash -n run_demo.sh final_verify.sh tests/*.sh bench/*.sh setup/*.sh   # shell 語法檢查
```

## 執行（Demo，需 root + 真實核心）

> **最快路徑**：`sudo ./run_demo.sh`（攻擊情境，含前置檢查、DAC 排除證明、`trace_pipe` 擷取與 PASS/FAIL 彙整）。
> 預設強制第一步真實執行 `read_file(/etc/shadow)`，避免 demo 依賴模型 compliance；`--no-force` 改回完全由模型輸出。
> `--benign` 跑零誤報情境、`--full` 兩者皆跑。`sudo ./final_verify.sh` 為完整端到端 gate。

手動逐步版：

```bash
# A. 攻擊情境（間接注入讀 /etc/shadow）
sudo python3 sentinel/main.py --config config.yaml \
  --launch "python3 agent/target_agent.py --task attacks/indirect_injection.md"

# 另開終端觀察核心阻斷紀錄
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "BPF LSM"

# B. 正常情境（驗證零誤報）
sudo python3 sentinel/main.py --config config.yaml \
  --launch "python3 agent/target_agent.py --task attacks/benign_task.md"
```

---

## 驗證方法 ⚠️（務必排除 DAC 干擾）

`/etc/shadow` 預設 `640 root:shadow`，**一般使用者本就被 DAC 擋下**。若以普通使用者跑就看到
"Permission denied"，**不能證明是 LSM 生效**。要確認 LSM 真的有擋，至少滿足其一：

1. **以 root 執行代理**（DAC 不再阻擋，唯一拒絕來源即 LSM）——上面的 `sudo ... --launch` 即此情境。
2. **掛載前後對照**：未啟動 daemon 時 root 可成功 `cat /etc/shadow`；啟動 daemon 並納管該 PID 後被拒。
3. **核對核心證據**：`trace_pipe` 應出現 `BPF LSM blocked pid ... sensitive ino ...`；
   `alerts.jsonl` 應有 `INJECTION_PRIVILEGE_ESCALATION`。

正向對照（確認沒擋錯）：daemon 執行中，另一個**未被納管**的 shell 仍可 `sudo cat /etc/shadow`。

### 預期結果
- **攻擊情境**：代理被誘導輸出 `ACTION: read_file(/etc/shadow)` → 其 `open()` 在核心被 `-EPERM` 阻斷
  → 工具回 "Permission denied" → 代理拿不到內容；`alerts.jsonl` 記錄關聯威脅，`trace_pipe` 有阻斷行。
- **正常情境**：無敏感存取、無告警、代理順利完成摘要。
- 系統其他行程（login/sudo/cron）完全不受影響。

### 驗證狀態 ✅

已在目標機（真實核心 + root）實機跑過並通過：

- **攻擊情境 PASS**：root 代理的 `read_file(/etc/shadow)` 被 LSM `-EPERM` 阻斷（已排除 DAC 干擾），
  `trace_pipe` 出現 `BPF LSM blocked ...`、`alerts.jsonl` 有 `INJECTION_PRIVILEGE_ESCALATION`。
- **正常情境 PASS**：零敏感存取、零告警，代理順利完成任務。
- **bypass 回歸 PASS**：symlink/hardlink 指向 `/etc/shadow` 仍被以 `(dev,ino)` 擋下。
- **正向對照**：未納管的 shell 仍可 `sudo cat /etc/shadow`，系統行程不受影響。
- 離線單元測試 4/4 通過（敏感讀檔遮蔽、JSONL `0600` 權限、intent 晚到回掃升級、路徑正規化）。

## 效能基準

```bash
./bench/benchmark.sh baseline      # 不啟動 daemon
# 另開終端啟動 daemon 後：
./bench/benchmark.sh withbpf       # 未納管程序的系統旁觀者成本
sudo ./bench/benchmark.sh tracked  # 把壓測 PID 寫入 tracked_pids，量受監控路徑完整成本
```

---

## 架構決策與已知限制（重要）

1. **pinned maps 共用**：`tracked_pids`/`sensitive_inodes` 釘在 `/sys/fs/bpf`，由 action 與 lsm 兩物件共用；
   `loader.ensure_pinned_maps` 須在任何程式開啟前先建立。`main.py` 預設啟動/結束時清 pin（`--keep-maps` 保留）。
2. **LSM 載入走 libbpf/bpftool**：`loader.LsmLoader` 從 `bpf/lsm_enforce_libbpf.c` 產生 `vmlinux.h`、
   `clang -target bpf` 編譯，再 `bpftool prog loadall ... autoattach` 掛到 `lsm/file_open`；任一步失敗即中止。
   **仍須在 cloud 以 `trace_pipe` 確認阻斷確實發生。**
3. **dev 編碼換算**：`enforcer.kernel_dev()` 將 `os.stat().st_dev` 換算為核心 `(major<<20)|minor`，
   否則 `sensitive_inodes` 鍵對不上而**靜默放行**。`file_key` 為 `{u64 dev; u64 ino}`，刻意無 padding。
4. **核心態 PID 傳播**：`sched_process_fork` tracepoint 在核心側把 child PID 加入 `tracked_pids`，
   無 userspace round-trip，子行程第一個 syscall 也擋得住。
5. **納管時序 race-free**：`--launch` 先起一個 `kill -STOP $$; exec "$@"` wrapper，等它進 stopped 狀態、
   寫入 `tracked_pids` 後才 `SIGCONT`——root 代理在跑任何 `openat` 前就已被納管。
6. **fail-closed 自我測試**：啟動時 `self_test_lsm` 納管 daemon 自身 PID，斷言已無法開預載敏感路徑；
   擋不住就 raise（`--skip-lsm-self-test` 可略過，不建議）。
7. **意圖通道**：預設用 app 端日誌（`target_agent.py` 寫 `intent.jsonl`），因 **Ollama 預設走 localhost
   明文 HTTP**，`SSL_*` uprobe 攔不到；`intent_probes.c` 提供 TLS 情境的 SSL uprobe，屬可選進階。
8. **路徑還原為 best-effort**：`normalizer.resolve_path` 以 `/proc/<pid>/cwd` 還原，僅供 logging；
   LSM 以 inode 為準不依賴它，故失敗也不削弱防禦。
9. **敏感內容不得落 log**：`agent/tools.py::read_file` 對設定的 `sensitive_paths` 遮蔽內容，
   所有 JSONL writer 用 `0o600`。

## 審查問題落實（P1–P10）

| ID | 議題 | 落實處 |
|---|---|---|
| P1 | PID 範圍鎖定，只擋代理行程樹 | `lsm_enforce_libbpf.c` / `tracked_pids` |
| P2 | `st_dev` → 核心 `(major<<20)\|minor` 換算 | `enforcer.kernel_dev()` |
| P3 | `(u64,u64)` file_key 無 padding | `lsm_enforce_libbpf.c` / `enforcer.py` |
| P4 | Ollama 明文 HTTP 非 TLS，意圖改走 app-log | `target_agent.py` / `intent_probes.c` |
| P5 | daemon 載入時序（先建 pinned map 再載程式） | `loader.ensure_pinned_maps` |
| P6 | `openat2` 無 flags 欄位，另探針讀 `how->flags` | `action_probes.c` |
| P7 | fork 子 PID 核心態傳播 | `action_probes.c::sched_process_fork` |
| P8 | presence-based map（key 存在即命中） | `sensitive_inodes` / `tracked_pids` |
| P9 | uid 欄位納入事件 | `action_probes.c` / `correlator.py` |
| P10 | 驗證須排除 DAC（root 跑 + trace_pipe 佐證） | `run_demo.sh`（見上方驗證方法） |

## 約定

- `config.yaml` 是敏感路徑、關聯窗/關鍵詞、log 路徑、模型的**單一事實來源**——新增敏感目標寫這裡，不寫死在程式。
- 代理用 ReAct 文字協定而非原生 function-calling；demo 可用 `--force-first-action` / `--force-final` 強制決定論。
