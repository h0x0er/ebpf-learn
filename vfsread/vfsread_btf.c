//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";


struct event_t{
    int size;
    u8 data[100];
    u8 exe[100];
};


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");


const struct event_t *unused __attribute__((unused));


// extern ssize_t vfs_read(struct file *, char __user *, size_t, loff_t *);

SEC("kprobe/vfs_read")
long BPF_KPROBE(vfs_read){

    struct event_t *event;

  
    event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if(!event){
        return 0;
    }

    
    bpf_get_current_comm(&event->exe , 100);
    bpf_probe_read_user(&event->data, 100, (void *)PT_REGS_PARM2(ctx));
    event->size = (int)PT_REGS_PARM3(ctx);


    bpf_ringbuf_submit(event, 0);


    // bpf_printk("[vfs_read] Exe: %s; data: %s; Size: %d",prog,data,total_size);

    return 0;

}