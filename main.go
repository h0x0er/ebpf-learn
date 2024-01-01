package main

import "h0x0er/ebpf-learn/vfsread"

func main() {

	// sysopen.Hook()
	// vfswrite.Hook()
	// dorenameat.Hook()
	vfsread.Hook()
	// getname.Hook()
	// dormdir.Hook()

	// uprobes

	// malloc.Hook()
	// printf.Hook()
	// openssl.Hook()
	// gethostbyname.Hook()

}
