probe="$1"

ret="$PWD"

cd $probe
rm bpf_*
go generate .
cd $ret


echo

# Comment below statements; if dont wish to build go-binary
echo "[!] Building epbf-learn.."
go build .
echo "[!!] Done building... :)"
