#!/bin/bash
# =============================================================================
# OCI cloud-init user-data (ASCII-only) for agent-sentinel target host
# Ubuntu 22.04/24.04 (aarch64, Ampere A1.Flex). One boot does:
#   1) eBPF/BCC toolchain + headers for the running kernel
#   2) Ollama (native ARM64) + best-effort model pull
#   3) mount + persist bpffs
#   4) enable BPF LSM (append ,bpf to lsm= in GRUB), then reboot once
# After boot (a few minutes + one auto-reboot), SSH in and verify:
#   cat /sys/kernel/security/lsm      # should contain bpf
#   ls  /sys/kernel/btf/vmlinux       # should exist
#   cat /var/log/agent-sentinel-cloudinit.log
# Note: this does NOT upload the agent-sentinel project code (git clone / scp it).
# =============================================================================
set -ux
export DEBIAN_FRONTEND=noninteractive

# Model to pre-pull. 24GB -> llama3:8b (default). 6GB -> llama3.2:3b
# (if you change this, also change ollama_model in config.yaml).
MODEL="llama3:8b"

LOG=/var/log/agent-sentinel-cloudinit.log
exec > >(tee -a "$LOG") 2>&1
echo "=== agent-sentinel cloud-init start: arch=$(uname -m) kernel=$(uname -r) ==="

# 1) eBPF/BCC toolchain + matching kernel headers
apt-get update -y
apt-get install -y bpfcc-tools python3-bpfcc python3-yaml python3-pip curl git
apt-get install -y "linux-headers-$(uname -r)" \
  || apt-get install -y linux-headers-oracle \
  || apt-get install -y linux-headers-generic
apt-get install -y libbpf-dev bpftool clang llvm || true
pip3 install ollama 2>/dev/null || pip3 install --break-system-packages ollama || true

# 2) Ollama (native ARM64) + best-effort model pull
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
fi
systemctl enable --now ollama || true
sleep 5
ollama pull "$MODEL" || echo "[warn] ollama pull $MODEL failed; run it manually after SSH"

# 3) mount + persist bpffs
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
grep -q '/sys/fs/bpf' /etc/fstab || echo 'bpf /sys/fs/bpf bpf defaults 0 0' >> /etc/fstab

# 4) enable BPF LSM: append ,bpf to current lsm list in GRUB
CUR="$(cat /sys/kernel/security/lsm 2>/dev/null)"
echo "current LSM list: ${CUR:-<none>}"
NEED_REBOOT=0
if [ -n "$CUR" ] && ! echo "$CUR" | grep -qw bpf; then
  if grep -q 'GRUB_CMDLINE_LINUX_DEFAULT=.*lsm=' /etc/default/grub; then
    sed -i "s/lsm=[^ \"]*/lsm=${CUR},bpf/" /etc/default/grub
  else
    sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT=\"/GRUB_CMDLINE_LINUX_DEFAULT=\"lsm=${CUR},bpf /" /etc/default/grub
  fi
  update-grub
  echo "wrote GRUB: lsm=${CUR},bpf (effective after reboot)"
  NEED_REBOOT=1
else
  echo "bpf already in LSM list, or list unreadable; not touching GRUB."
fi

# 5) BTF check (informational)
if [ -f /sys/kernel/btf/vmlinux ]; then
  echo "BTF present (CO-RE OK)"
else
  echo "[warn] missing /sys/kernel/btf/vmlinux; if needed 'apt install linux-generic' then reboot"
fi

echo "=== agent-sentinel cloud-init done (model=$MODEL) ==="
touch /var/lib/agent-sentinel-cloudinit.done

# 6) reboot once if GRUB changed (to activate BPF LSM)
if [ "$NEED_REBOOT" = "1" ]; then
  echo "rebooting in 10s to apply BPF LSM ..."
  sleep 10
  reboot
fi


