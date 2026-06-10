// =============================================================================
// action_probes.c — M1 行為擷取層（BCC / 核心邊界）
// -----------------------------------------------------------------------------
// 探針：
//   - sched:sched_process_fork  → 於「核心態」把追蹤狀態由父傳給子（解決 P7 race）
//   - syscalls:sys_enter_execve → 記錄子行程創建（forensics）
//   - syscalls:sys_enter_openat / sys_enter_openat2 → 記錄檔案開啟
// 與 lsm_enforce.c 共用的 pinned map：tracked_pids（/sys/fs/bpf/tracked_pids）
// 全部事件經單一 ring buffer `events` 零拷貝送往使用者空間。
//
// 注意：本檔由 BCC 在目標機上以核心標頭即時編譯，BCC rewriter 會自動為
//       kernel 指標解參考插入 bpf_probe_read。需 kernel >= 5.6（openat2 tracepoint）。
// =============================================================================
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN  256

// 本地定義 open_how 佈局（ABI 穩定），避免相依 uapi/linux/openat2.h 的路徑差異。
// 註：tracepoint 的 args->how 為「指標」，僅讀其值再 bpf_probe_read_user 進此結構，
//     故不需要 uapi 的完整定義。
struct open_how_compat {
    u64 flags;
    u64 mode;
    u64 resolve;
};

enum event_type {
    EVT_FORK = 1,
    EVT_EXEC = 2,
    EVT_OPEN = 3,
};

// 與使用者空間 normalizer 對齊的事件結構（欄位順序/型別需與 Python 解碼一致）
struct event_t {
    u32  type;
    u32  pid;
    u32  ppid;
    u32  uid;
    u64  timestamp;            // bpf_ktime_get_ns()，CLOCK_MONOTONIC（與 agent intent 同時鐘）
    s32  flags;                // open flags（EVT_OPEN 有效）
    char comm[TASK_COMM_LEN];
    char path[MAX_PATH_LEN];   // open/exec 的路徑；fork 放子行程 comm
};

BPF_RINGBUF_OUTPUT(events, 256);   // 256 個 page ≈ 1 MB
// 與 lsm_enforce.c 同名同型的 pinned map（先載入者建立並 pin，後載入者沿用）
BPF_TABLE_PINNED("hash", u32, u8, tracked_pids, 10240, "/sys/fs/bpf/tracked_pids");

static __always_inline int is_tracked(u32 pid)
{
    u8 *v = tracked_pids.lookup(&pid);
    return v != 0;
}

// ----- fork：核心態傳播追蹤狀態（避免子行程首個 syscall 漏網，對應 P7）-----
TRACEPOINT_PROBE(sched, sched_process_fork)
{
    u32 ppid = (u32)args->parent_pid;
    u32 cpid = (u32)args->child_pid;

    if (!is_tracked(ppid))
        return 0;

    u8 one = 1;
    tracked_pids.update(&cpid, &one);   // 子行程即刻納管，無使用者空間 round-trip

    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return 0;
    e->type      = EVT_FORK;
    e->pid       = cpid;
    e->ppid      = ppid;
    e->uid       = (u32)bpf_get_current_uid_gid();
    e->timestamp = bpf_ktime_get_ns();
    e->flags     = 0;
    bpf_probe_read_kernel_str(&e->comm, sizeof(e->comm), args->child_comm);
    e->path[0]   = '\0';
    events.ringbuf_submit(e, 0);
    return 0;
}

// ----- execve：記錄受監控代理衍生的子行程 -----
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid))
        return 0;

    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return 0;
    e->type      = EVT_EXEC;
    e->pid       = pid;
    e->ppid      = 0;
    e->uid       = (u32)bpf_get_current_uid_gid();
    e->timestamp = bpf_ktime_get_ns();
    e->flags     = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->path, sizeof(e->path), (void *)args->filename);
    events.ringbuf_submit(e, 0);
    return 0;
}

// ----- openat：核心訴求，擷取檔案開啟 -----
TRACEPOINT_PROBE(syscalls, sys_enter_openat)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid))
        return 0;

    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return 0;
    e->type      = EVT_OPEN;
    e->pid       = pid;
    e->ppid      = 0;
    e->uid       = (u32)bpf_get_current_uid_gid();
    e->timestamp = bpf_ktime_get_ns();
    e->flags     = args->flags;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->path, sizeof(e->path), (void *)args->filename);
    events.ringbuf_submit(e, 0);
    return 0;
}

// ----- openat2：flags 位於 struct open_how，需另寫探針（對應 P6）-----
TRACEPOINT_PROBE(syscalls, sys_enter_openat2)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid))
        return 0;

    struct event_t *e = events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return 0;
    e->type      = EVT_OPEN;
    e->pid       = pid;
    e->ppid      = 0;
    e->uid       = (u32)bpf_get_current_uid_gid();
    e->timestamp = bpf_ktime_get_ns();

    struct open_how_compat how = {};
    bpf_probe_read_user(&how, sizeof(how), (void *)args->how);  // how->flags 為 __u64
    e->flags     = (s32)how.flags;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->path, sizeof(e->path), (void *)args->filename);
    events.ringbuf_submit(e, 0);
    return 0;
}
