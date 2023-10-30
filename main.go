package main

import (
	"h0x0er/ebpf-learn/uprobes/malloc"
)

func main() {

	// sysopen.Hook()
	// vfswrite.Hook()
	// dorenameat.Hook()
	// vfsread.Hook()
	// getname.Hook()
	// dormdir.Hook()

	// uprobes

	malloc.Hook()

}
