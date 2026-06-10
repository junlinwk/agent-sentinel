// =============================================================================
// lsm_enforce.c — M2b 主動阻斷層（BCC / BPF LSM）
// -----------------------------------------------------------------------------
// 掛載點：lsm/file_open（VFS 解析完最終 file 物件後、授權前），無 TOCTOU。
// 判定：只對 AI 代理行程樹（tracked_pids）生效，且命中敏感 inode 才回 -EPERM。
//
// 與 action_probes.c 共用 pinned map：
//   - tracked_pids      : 由 fork 探針於核心態維護的代理行程樹
//   - sensitive_inodes  : 由使用者空間 enforcer.py 以 (kernel_dev, ino) 載入
//
// 重要（對應 P1）：必須有 tracked_pids 判定，否則會擋下 login/su/sudo/
//   unix_chkpwd/cron(PAM)/sshd 等正常讀 /etc/shadow 的系統行程，導致整機鎖死。
// 重要（對應 P2）：sensitive_inodes 的 dev 鍵須為「核心 dev_t = (major<<20)|minor」，
//   使用者空間 os.stat().st_dev 需換算（見 enforcer.py），否則永遠查不到 → 靜默放行。
//
// LSM_PROBE 函式名為 lsm__file_open，BCC 於載入時自動掛載（kernel >= 5.7，
//   且開機參數 lsm=...,bpf 已啟用）。
// =============================================================================
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/errno.h>

// 兩個 u64：無對齊 padding，確保與使用者空間建鍵的 16-byte 佈局一致（對應 P3）
struct file_key {
    u64 dev;
    u64 ino;
};

BPF_TABLE_PINNED("hash", struct file_key, u8, sensitive_inodes, 4096, "/sys/fs/bpf/sensitive_inodes");
BPF_TABLE_PINNED("hash", u32, u8, tracked_pids, 10240, "/sys/fs/bpf/tracked_pids");

LSM_PROBE(file_open, struct file *file)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // ★ 只對 AI 代理行程樹生效（見上方 P1 說明）
    u8 *tracked = tracked_pids.lookup(&pid);
    if (!tracked)
        return 0;

    struct inode *inode = file->f_inode;       // BCC rewriter 自動以 bpf_probe_read 取值
    if (!inode)
        return 0;
    struct super_block *sb = inode->i_sb;
    if (!sb)
        return 0;

    struct file_key key = {};
    key.ino = inode->i_ino;
    key.dev = sb->s_dev;                        // 核心 dev_t：MKDEV = (major<<20)|minor

    u8 *blocked = sensitive_inodes.lookup(&key);   // presence-based（對應 P8）
    if (blocked) {
        bpf_trace_printk("BPF LSM blocked pid %d sensitive ino %llu\n", pid, key.ino);
        return -EPERM;                          // VFS 底層原子性拒絕
    }
    return 0;
}
