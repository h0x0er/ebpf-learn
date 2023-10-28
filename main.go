package main

import (
	"h0x0er/ebpf-learn/getname"
)

func main() {

	// sysopen.Hook()
	// vfswrite.Hook()
	// dorenameat.Hook()
	// vfsread.Hook()

	getname.Hook()

	// dormdir.Hook()

}
