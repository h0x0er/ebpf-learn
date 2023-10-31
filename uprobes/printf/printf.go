package printf

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event_t -target amd64 bpf printf_btf.c -- -I../../includes

func Hook() {

	libcPath := "/lib/x86_64-linux-gnu/libc.so.6"

	// hook docker library
	libcPath = "/var/lib/docker/overlay2/210b3c4bd9d0e4c75147a2bcf26928d5dd3e6a0691c1d0af8368ea06bd2d6ee1/diff/lib/libc.musl-x86_64.so.1"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	libc, err := link.OpenExecutable(libcPath)
	if err != nil {
		log.Fatal(err)
	}
	link, err := libc.Uprobe("printf", objs.HookPrintf, nil)

	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()

	rb, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("[ringbuf] %s", err)
	}
	defer rb.Close()

	var event bpfEventT

	for {

		record, err := rb.Read()
		if err != nil {
			continue
		}

		if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("[binaryRead] error parsing event: %s", err)
		}
		log.Printf("[printf] Prog: %s; PrintFormat: %s", unix.ByteSliceToString(event.Exe[:]), string(event.PrintfFormat[:]))

	}

}
