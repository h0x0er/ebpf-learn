//go:build ignore


#include "common.h"


char __license[] SEC("license") = "Dual MIT/GPL";


SEC("kprobe/do_rmdir")
long BPF_KPROBE(do_rmdir){

    char src[20];

    struct filename del_file;
    int err;
    
    err = bpf_probe_read_kernel(&del_file, sizeof(struct filename), (void *)PT_REGS_PARM2(ctx));

    if(err){
        bpf_printk("unable to read filename struct");
    }

    bpf_probe_read_user_str(&src, 20, del_file.uptr);

    char prog[30];
    bpf_get_current_comm(&prog , 30);




    bpf_printk("[do_rmdir] exe: %s; filename: %s",prog, src);


    return 0;

}