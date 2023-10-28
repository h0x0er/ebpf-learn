package getname

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event_t -target amd64 bpf getname_btf.c -- -I../includes

//

//

func Hook() {

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

	link, err := link.Kprobe("getname", objs.GetName, nil)

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

		log.Printf("[getname] Prog: %s; FileName: %s\n", unix.ByteSliceToString(event.Exe[:]), unix.ByteSliceToString(event.Filename[:]))

	}

}
