package golibsecp256k1

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// abortChildEnv selects which edge case the re-invoked test binary runs.
const abortChildEnv = "GOLIBSECP256K1_ABORT_CHILD"

// abortCases are inputs that, before the return codes were checked, made the cgo backend
// hand an unparsed or zeroed struct to libsecp256k1, whose default illegal-argument
// callback then aborted the whole process (SIGABRT). Each one runs in a child process,
// because an abort kills whatever runs it; the parent asserts that the child returns.
var abortCases = map[string]func(){
	"PubKeyAdd(P, -P)": func() {
		p, negP := keyPairSummingToInfinity()
		_, err := PubKeyAdd(&p, &negP)
		fmt.Printf("err=%v\n", err)
	},
	"PubKeyAdd(invalid, P)": func() {
		p, _ := keyPairSummingToInfinity()
		var bad [33]byte
		_, err := PubKeyAdd(&bad, &p)
		fmt.Printf("err=%v\n", err)
	},
	"PubKeyNegate(invalid)": func() {
		var bad [33]byte
		err := PubKeyNegate(&bad)
		fmt.Printf("err=%v\n", err)
	},
	"PubKeyTweakMul(invalid, 3)": func() {
		var bad [33]byte
		tweak := [32]byte{31: 3}
		fmt.Printf("err=%v\n", PubKeyTweakMul(&bad, &tweak))
	},
	"SecKeyAdd(1, n-1)": func() {
		one := [32]byte{31: 1}
		nm1 := [32]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
			0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40}
		fmt.Printf("err=%v\n", SecKeyAdd(&one, &nm1))
	},
	"PubKeyFromSecKey(0)": func() {
		var zero [32]byte
		fmt.Printf("pk=%x\n", PubKeyFromSecKey(&zero))
	},
}

// TestNoAbortOnInvalidInput proves no edge case can abort the process: each case is run
// in a re-invoked test binary and must exit normally, never with libsecp256k1's
// "illegal argument" abort.
func TestNoAbortOnInvalidInput(t *testing.T) {
	if name := os.Getenv(abortChildEnv); name != "" {
		abortCases[name]()
		return
	}
	for name := range abortCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cmd := exec.Command(os.Args[0], "-test.run=^TestNoAbortOnInvalidInput$", "-test.count=1")
			cmd.Env = append(os.Environ(), abortChildEnv+"="+name)
			out, err := cmd.CombinedOutput()
			if err != nil || strings.Contains(string(out), "SIGABRT") || strings.Contains(string(out), "illegal argument") {
				t.Fatalf("%s killed the process (%v):\n%s", name, err, out)
			}
		})
	}
}

// keyPairSummingToInfinity returns P and -P: the same x with opposite parity.
func keyPairSummingToInfinity() ([33]byte, [33]byte) {
	sk := [32]byte{31: 7}
	p := *PubKeyFromSecKey(&sk)
	negP := p
	negP[0] ^= 0x01
	return p, negP
}
