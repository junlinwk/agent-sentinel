// SPDX-License-Identifier: GPL-2.0
// libbpf variant of lsm_enforce.c for kernels/BCC builds where BCC LSM attach
// cannot resolve the BTF target name.
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1

struct file_key {
    __u64 dev;
    __u64 ino;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct file_key);
    __type(value, __u8);
} sensitive_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u8);
} tracked_pids SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(enforce_file_open, struct file *file)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
    if (!tracked)
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    if (!sb)
        return 0;

    struct file_key key = {};
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = BPF_CORE_READ(sb, s_dev);

    __u8 *blocked = bpf_map_lookup_elem(&sensitive_inodes, &key);
    if (blocked) {
        bpf_printk("BPF LSM blocked pid %d sensitive ino %llu\n", pid, key.ino);
        return -EPERM;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
