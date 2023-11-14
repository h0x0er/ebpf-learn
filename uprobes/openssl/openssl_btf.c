//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event_t
{
    u8 exe[100];
    u8 data[200];
    u64 _time_;
};

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

const struct event_t *unused __attribute__((unused));

SEC("uprobe/ssl_write")
int hook_ssl_write(struct pt_regs *ctx)
{

    struct event_t *event;
    event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if (!event)
    {
        return 0;
    }

    bpf_get_current_comm(&event->exe, 100);

    bpf_probe_read_user_str(event->data, 200, (void*)PT_REGS_PARM2(ctx));
    
    
    event->_time_ = bpf_ktime_get_boot_ns();
    
    bpf_ringbuf_submit(event, 0);

    return 0;
}