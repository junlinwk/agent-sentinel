#!/usr/bin/env bash
# =============================================================================
# 00_setup_env.sh — 在目標機（Ubuntu 22.04，x86-64 或 ARM64）建置 agent-sentinel 環境
# 需以具 sudo 權限的使用者執行。本腳本不會自動改 GRUB（避免開機風險），僅引導。
# =============================================================================
set -euo pipefail

say()  { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*"; }

say "arch=$(uname -m) kernel=$(uname -r)"

# 1) 工具鏈 ------------------------------------------------------------------
say "安裝 eBPF/BCC 工具鏈與相依套件 ..."
sudo apt-get update -y
sudo apt-get install -y \
  bpfcc-tools python3-bpfcc libbpf-dev bpftool clang llvm \
  linux-headers-"$(uname -r)" python3-pip curl
pip3 install --user -r "$(dirname "$0")/../requirements.txt"

# 2) BTF ---------------------------------------------------------------------
if [ -f /sys/kernel/btf/vmlinux ]; then ok "BTF 存在（CO-RE 可用）"; else err "缺少 /sys/kernel/btf/vmlinux"; fi

# 3) bpffs -------------------------------------------------------------------
if mount | grep -q 'bpf on /sys/fs/bpf'; then
  ok "bpffs 已掛載於 /sys/fs/bpf"
else
  warn "bpffs 未掛載，嘗試掛載 ..."
  sudo mount -t bpf bpf /sys/fs/bpf && ok "已掛載 bpffs" || err "無法掛載 bpffs"
fi

# 4) BPF LSM 啟用檢查（關鍵）-------------------------------------------------
if grep -q 'CONFIG_BPF_LSM=y' "/boot/config-$(uname -r)" 2>/dev/null; then
  ok "CONFIG_BPF_LSM=y"
else
  warn "未偵測到 CONFIG_BPF_LSM=y（部分核心仍可能內建）"
fi

if grep -qw bpf /sys/kernel/security/lsm; then
  ok "bpf 已在啟用的 LSM 清單中：$(cat /sys/kernel/security/lsm)"
else
  warn "bpf 不在 LSM 清單，需手動啟用後重開機："
  cat <<EOF
  ----------------------------------------------------------------------------
  目前清單： $(cat /sys/kernel/security/lsm)
  1) 編輯 /etc/default/grub，將 GRUB_CMDLINE_LINUX 設為（保留現有清單後綴 ,bpf）：
       GRUB_CMDLINE_LINUX="lsm=$(cat /sys/kernel/security/lsm),bpf"
  2) sudo update-grub && sudo reboot
  3) 重開後： cat /sys/kernel/security/lsm  應可看到 bpf
  ----------------------------------------------------------------------------
EOF
fi

# 5) eBPF 冒煙測試 -----------------------------------------------------------
say "eBPF 冒煙測試（opensnoop 2 秒）..."
if sudo timeout 2 /usr/sbin/opensnoop-bpfcc >/dev/null 2>&1; then ok "eBPF 可載入"; else warn "opensnoop 測試未通過（檢查權限/核心）"; fi

# 6) Ollama + 模型 -----------------------------------------------------------
if ! command -v ollama >/dev/null 2>&1; then
  say "安裝 Ollama ..."
  curl -fsSL https://ollama.com/install.sh | sh
fi
say "下載 Llama 3 8B（首次較久）..."
ollama pull llama3:8b || warn "ollama pull 失敗，稍後手動執行 'ollama pull llama3:8b'"

ok "環境建置流程結束。若上方有 'bpf 不在 LSM 清單' 警告，請先啟用並重開機。"
echo "下一步： sudo python3 sentinel/main.py --config config.yaml --launch \\"
echo "          \"python3 agent/target_agent.py --task attacks/indirect_injection.md\""
