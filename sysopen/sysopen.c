//go:build ignore


#include "common.h"


char __license[] SEC("license") = "Dual MIT/GPL";

// long do_sys_open(int dfd, const char __user *filename, int flags,
			// umode_t mode);

SEC("kprobe/do_sys_open")
long BPF_KPROBE(e){

    char filename[20];

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_probe_read_user(&filename,20,(void *)PT_REGS_PARM2(ctx));

    bpf_printk("[do_sys_open] pid:%d; filename: %s",pid, filename);


    return 0;

}