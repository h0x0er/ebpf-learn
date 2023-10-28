//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";


struct event_t{
    u8 query[100];
};


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");


const struct event_t *unused __attribute__((unused));


// int dns_query(struct net *net,
// 	      const char *type, const char *name, size_t namelen,
// 	      const char *options, char **_result, time64_t *_expiry,
// 	      bool invalidate)

SEC("kprobe/dns_query")
int BPF_KPROBE(dns_query){

    struct event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if(!event){
        return 0;
    }
    
    bpf_probe_read_kernel(&event->query, 100, (void *)PT_REGS_PARM3(ctx));

    bpf_ringbuf_submit(event, 0);

    return 0;

}