// =============================================================================
// intent_probes.c — M1b 意圖擷取層【可選 / 進階：零侵入式】
// -----------------------------------------------------------------------------
// 預設的 MVP 意圖來源是「app 端日誌」（agent/target_agent.py 直接寫 intent.jsonl，
// 由 correlator 讀取）。本檔提供「零侵入式」替代：以 uprobe 掛 libssl 的
// SSL_read / SSL_write，於加密前、解密後擷取明文。
//
// ⚠️ 傳輸通道須先確認（對應 P4）：
//   - Ollama 預設於 localhost:11434 走「明文 HTTP（非 TLS）」→ SSL_* uprobe 攔不到，
//     此情境應改掛 kprobe tcp_sendmsg/tcp_recvmsg（見檔尾說明），或沿用 MVP app-log。
//   - 僅當代理改走 HTTPS/TLS 時，下方 SSL_* uprobe 才適用。
//
// 本檔「未」被 main.py 預設載入；如需啟用，見 sentinel/loader.py 的 IntentLoader
// 與 README 的「進階：zero-instrumentation 意圖擷取」。
// =============================================================================
#include <uapi/linux/ptrace.h>

#define MAX_BUF 256

struct ssl_event_t {
    u32  pid;
    u32  uid;
    u64  timestamp;          // CLOCK_MONOTONIC，與行為事件同時鐘
    s32  direction;          // 0 = SSL_read（回應/輸入解密後），1 = SSL_write（送出/加密前）
    s32  len;                // 實際位元組數（可能 > MAX_BUF，僅擷取前 MAX_BUF）
    char data[MAX_BUF];
};

BPF_RINGBUF_OUTPUT(ssl_events, 256);
BPF_TABLE_PINNED("hash", u32, u8, tracked_pids, 10240, "/sys/fs/bpf/tracked_pids");
// 暫存 SSL_read 進入點的 buffer 指標，於返回點讀取（buffer 返回後才填好）
BPF_HASH(read_bufs, u32, u64);

static __always_inline int tracked(u32 pid)
{
    u8 *v = tracked_pids.lookup(&pid);
    return v != 0;
}

// ---- SSL_write(SSL *ssl, const void *buf, int num)：送出前即為明文 ----
int uprobe_ssl_write(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!tracked(pid))
        return 0;

    void *buf = (void *)PT_REGS_PARM2(ctx);
    int num   = (int)PT_REGS_PARM3(ctx);
    if (num <= 0)
        return 0;

    struct ssl_event_t *e = ssl_events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return 0;
    e->pid       = pid;
    e->uid       = (u32)bpf_get_current_uid_gid();
    e->timestamp = bpf_ktime_get_ns();
    e->direction = 1;
    e->len       = num;
    u32 cap = num < MAX_BUF ? num : MAX_BUF;
    bpf_probe_read_user(&e->data, cap, buf);
    ssl_events.ringbuf_submit(e, 0);
    return 0;
}

// ---- SSL_read 進入點：暫存 buffer 指標（此時尚未填入明文）----
int uprobe_ssl_read_enter(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!tracked(pid))
        return 0;
    u64 buf = (u64)PT_REGS_PARM2(ctx);
    read_bufs.update(&pid, &buf);
    return 0;
}

// ---- SSL_read 返回點：回傳值為讀入位元組數，buffer 已是明文 ----
int uretprobe_ssl_read_return(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    int ret = PT_REGS_RC(ctx);
    u64 *bufp = read_bufs.lookup(&pid);
    if (!bufp)
        return 0;
    read_bufs.delete(&pid);
    if (ret <= 0)
        return 0;

    struct ssl_event_t *e = ssl_events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return 0;
    e->pid       = pid;
    e->uid       = (u32)bpf_get_current_uid_gid();
    e->timestamp = bpf_ktime_get_ns();
    e->direction = 0;
    e->len       = ret;
    u32 cap = ret < MAX_BUF ? ret : MAX_BUF;
    bpf_probe_read_user(&e->data, cap, (void *)*bufp);
    ssl_events.ringbuf_submit(e, 0);
    return 0;
}

// =============================================================================
// 若目標是「明文 HTTP（Ollama 預設）」，請改以 kprobe 擷取 loopback 流量，概念：
//
//   int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
//                           struct msghdr *msg, size_t size) {
//       u32 pid = bpf_get_current_pid_tgid() >> 32;
//       if (!tracked(pid)) return 0;
//       // 由 msg->msg_iter 取得 iovec base，bpf_probe_read_user 擷取前 N bytes，
//       // 再於使用者空間重組 HTTP/JSON。實作較繁瑣，故 MVP 採 app-log。
//   }
//
// 由於 msghdr/iov 走訪在不同核心版本差異大且易踩 verifier，建議優先採用
// MVP 的 app 端日誌路徑；本 SSL uprobe 區塊則用於代理改走 TLS 的情境。
// =============================================================================
