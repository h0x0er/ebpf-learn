//go:build ignore


#include "common.h"


char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write){

    char data[100];

    size_t s = PT_REGS_PARM3(ctx);


    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    int ret = bpf_probe_read_user(&data, 100, (void *)PT_REGS_PARM2(ctx));

    bpf_printk("[vfs_write] pid:%d; size: %d; data: %s",pid, s, data);

    return 0;

}