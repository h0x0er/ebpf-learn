# Learning eBPF

## "vmlinux.h" header file

To use kernel structs, run below command to generate a header file containing all structs.

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

Then include it into your all `btf programs` at the top.
```c
#include "vmlinux.h"
```



**Refer:**
* [includes folder](includes/)
* https://blog.aquasec.com/vmlinux.h-ebpf-programs


## "common.h" header file

I have included all the required headers in this single file.Simply include this file and start developing.

header file: [common.h](includes/common.h)

## go generate: 

**specify custom headers**
```go
// go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf dorenameat_btf.c -- -I../includes
```
**generate go structs**

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type <name of c_struct here> -target amd64 bpf dorenameat_btf.c -- -I../includes
```
Checkout: [vfsread_btf.c](vfsread/vfsread_btf.c)

## for reading kernel struct from arguments

```c
...
    char src[20];
    struct filename src_file;

    int err;

    // populate the src_file struct.
    err = bpf_probe_read_kernel(&src_file, sizeof(struct filename), (void *)PT_REGS_PARM2(ctx));

    // read field just like accessing normal structs
    bpf_probe_read_user(&src, 20, src_file.uptr);
...

```

Checkout: [dorenameat_btf.c](dorenameat/dorenameat_btf.c)

Refer: https://github.com/iovisor/bcc/issues/2534



## using ringbuffer

**Step1:** declare ringbuf & event to put into the ringbuf.
```c
...

// ringbuf declaration
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// event to put into ringbuf
struct event_t{
    u8 exe[100];
    u8 filename_[100];
};
...

```
**Step2:** reserve some memory in the ringbuf & submit

```c
...

struct event_t *event;

event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
if(!event){
    return 0;
}

// populate the event to send;
bpf_get_current_comm(&event->exe , 100);

// put into ringbuf
bpf_ringbuf_submit(event, 0);

...


```

Refer for btfcode: [getname_btf.c](getname/getname_btf.c)




## to read  trace events

When `bpf_printk` is used; then the logs can be read using below command.

```sh
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Refer: [log.sh](log.sh)


## to get list of kprobes
```sh
cat /proc/kallsyms
```





## References

https://sysdig.com/blog/the-art-of-writing-ebpf-programs-a-primer/

https://www.oreilly.com/library/view/linux-observability-with/9781492050193/ch04.html

https://docs.kernel.org/bpf/
https://man7.org/linux/man-pages/man7/bpf-helpers.7.html


https://github.com/cilium/ebpf/blob/main/docs/ebpf/guides/getting-started.md


https://android.googlesource.com/platform/external/bcc/+/refs/heads/android10-c2f2-s1-release/docs/reference_guide.md

https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/

https://thegraynode.io/posts/bpf_dev_env/

https://elixir.bootlin.com/linux/latest/source/tools/testing/selftests/bpf/progs


https://stackoverflow.com/questions/70905815/how-to-read-all-parameters-from-a-function-ebpf





