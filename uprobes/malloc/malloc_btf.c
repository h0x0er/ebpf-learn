//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";


struct event_t{
    u8 exe[100];
    size_t malloc_size;
};


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");



const struct event_t *unused __attribute__((unused));


SEC("uprobe/malloc")
int hook_malloc(struct pt_regs* ctx){

    struct event_t *event;
    event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if(!event){
        return 0;
    }
    
    bpf_get_current_comm(&event->exe , 100);
    event->malloc_size = PT_REGS_PARM1(ctx);

    bpf_ringbuf_submit(event, 0);

    return 0;

}