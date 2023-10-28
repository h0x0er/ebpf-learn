//go:build ignore


#include "common.h"


char __license[] SEC("license") = "Dual MIT/GPL";

// int do_renameat2(int olddfd, struct filename *oldname, int newdfd,
		//  struct filename *newname, unsigned int flags);

SEC("kprobe/do_renameat2")
long BPF_KPROBE(do_renameat2){

    char src[20];
    char dst[20];

   
    struct filename src_file;
    struct filename dst_file;


    int err;
    
    err = bpf_probe_read_kernel(&src_file, sizeof(struct filename), (void *)PT_REGS_PARM2(ctx));

    if(err){
        bpf_printk("unable to read filename struct");
    }

    err = bpf_probe_read_kernel(&dst_file, sizeof(struct filename), (void *)PT_REGS_PARM4(ctx));

    if(err){
        bpf_printk("unable to read filename struct");
    }


    bpf_probe_read_user(&src, 20, src_file.uptr);
    bpf_probe_read_user(&dst, 20, dst_file.uptr);


    char prog[30];
    bpf_get_current_comm(&prog , 30);




    bpf_printk("[do_renameat2] exe: %s; DST: %s; SRC: %s",prog,dst, src);


    return 0;

}