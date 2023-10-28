probe="$1"

cd $probe
rm bpf_*
go generate .
cd ..



echo

# Comment below statements; if dont wish to build go-binary
echo "[!] Building epbf-learn.."
go build .
echo "[!!] Done building... :)"
