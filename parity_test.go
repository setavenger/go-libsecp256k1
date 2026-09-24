package golibsecp256k1

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// This file runs unchanged under both backends (`go test` and `go test -tags
// libsecp256k1`) against the same golden values and the same errors, so passing under
// both builds means both backends return identical outputs and identical errors.

func h32(s string) [32]byte { return ConvertToFixedLength32(mustHex(s)) }
func h33(s string) [33]byte { return ConvertToFixedLength33(mustHex(s)) }

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var (
	// Scalars.
	sk0     = [32]byte{}
	sk1     = [32]byte{31: 1}
	sk2     = [32]byte{31: 2}
	sk3     = [32]byte{31: 3}
	sk6     = [32]byte{31: 6}
	skN     = h32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141") // group order n
	skNm1   = h32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140") // n - 1
	skMax   = h32("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	pointG  = h33("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	pointNG = h33("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798") // -G
	point2G = h33("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
	point3G = h33("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")

	// Invalid 33-byte encodings.
	badEncodings = map[string][33]byte{
		"all zero":         {},
		"x not on curve":   {0: 0x02, 32: 0x05},
		"x >= p":           h33("02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		"uncompressed tag": func() [33]byte { p := pointG; p[0] = 0x04; return p }(),
		"hybrid tag":       func() [33]byte { p := pointG; p[0] = 0x06; return p }(),
		"x = 0":            {0: 0x03},
	}
)

// wantErr checks err against the expected error: nil, or the same text and the same
// errors.Is classes.
func wantErr(t *testing.T, got, want error, classes ...error) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Fatalf("unexpected error %v", got)
		}
		return
	}
	if got == nil {
		t.Fatalf("got no error, want %q", want)
	}
	if got.Error() != want.Error() {
		t.Fatalf("error %q, want %q", got, want)
	}
	for _, c := range classes {
		if !errors.Is(got, c) {
			t.Fatalf("error %q does not match %q under errors.Is", got, c)
		}
	}
}

func TestParityPubKeyAdd(t *testing.T) {
	type tc struct {
		name    string
		a, b    [33]byte
		want    [33]byte
		wantErr error
	}
	cases := []tc{
		{"G + 2G", pointG, point2G, point3G, nil},
		{"G + (-G) is infinity", pointG, pointNG, [33]byte{}, ErrPointAtInfinity},
		{"-G + G is infinity", pointNG, pointG, [33]byte{}, ErrPointAtInfinity},
		{"G + G", pointG, pointG, point2G, nil},
	}
	for name, bad := range badEncodings {
		cases = append(cases,
			tc{"first " + name, bad, pointG, [33]byte{}, ErrInvalidPubKey},
			tc{"second " + name, pointG, bad, [33]byte{}, ErrInvalidPubKey})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, b := c.a, c.b
			got, err := PubKeyAdd(&a, &b)
			wantErr(t, err, c.wantErr, c.wantErr)
			if got != c.want {
				t.Fatalf("sum %x, want %x", got, c.want)
			}
			if a != c.a || b != c.b {
				t.Fatal("inputs were modified")
			}
		})
	}
}

// The oracle skips a transaction whose input keys sum to infinity by matching this
// substring; both backends must keep producing it.
func TestPointAtInfinityKeepsOracleSkipText(t *testing.T) {
	a, b := pointG, pointNG
	_, err := PubKeyAdd(&a, &b)
	if err == nil || !strings.Contains(err.Error(), "not on secp256k1 curve") {
		t.Fatalf("PubKeyAdd(G, -G) error %v, want one containing %q", err, "not on secp256k1 curve")
	}
}

func TestParityPubKeyNegate(t *testing.T) {
	type tc struct {
		name    string
		in      [33]byte
		want    [33]byte
		wantErr error
	}
	cases := []tc{
		{"G", pointG, pointNG, nil},
		{"-G", pointNG, pointG, nil},
	}
	for name, bad := range badEncodings {
		cases = append(cases, tc{name, bad, bad, ErrInvalidPubKey})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.in
			wantErr(t, PubKeyNegate(&p), c.wantErr, c.wantErr)
			if p != c.want {
				t.Fatalf("result %x, want %x", p, c.want)
			}
		})
	}
}

func TestParityPubKeyFromSecKey(t *testing.T) {
	for _, c := range []struct {
		name    string
		sk      [32]byte
		want    [33]byte
		wantErr error
	}{
		{"1", sk1, pointG, nil},
		{"2", sk2, point2G, nil},
		{"n-1", skNm1, pointNG, nil},
		{"0", sk0, [33]byte{}, ErrInvalidSecKey},
		{"n", skN, [33]byte{}, ErrInvalidSecKey},
		{"2^256-1", skMax, [33]byte{}, ErrInvalidSecKey},
	} {
		t.Run(c.name, func(t *testing.T) {
			sk := c.sk
			got, err := PubKeyFromSecKeyChecked(&sk)
			wantErr(t, err, c.wantErr, c.wantErr)
			if got != c.want {
				t.Fatalf("pubkey %x, want %x", got, c.want)
			}
			legacy := PubKeyFromSecKey(&sk)
			if c.wantErr != nil {
				if legacy != nil {
					t.Fatalf("PubKeyFromSecKey = %x, want nil for an invalid key", *legacy)
				}
			} else if legacy == nil || *legacy != c.want {
				t.Fatalf("PubKeyFromSecKey = %v, want %x", legacy, c.want)
			}
		})
	}
}

// scalarCase covers the in-place secret key tweaks: on error the key must be unchanged.
type scalarCase struct {
	name       string
	key, tweak [32]byte
	want       [32]byte
	cause      error
}

func runScalarCases(t *testing.T, op func(k, tw *[32]byte) error, opErr error, cases []scalarCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, tw := c.key, c.tweak
			err := op(&k, &tw)
			if c.cause == nil {
				wantErr(t, err, nil)
			} else {
				wantErr(t, err, wrapErr(opErr, c.cause), opErr, c.cause)
			}
			if k != c.want {
				t.Fatalf("key %x, want %x", k, c.want)
			}
			if tw != c.tweak {
				t.Fatal("tweak was modified")
			}
		})
	}
}

func TestParitySecKeyAdd(t *testing.T) {
	runScalarCases(t, SecKeyAdd, ErrTweak, []scalarCase{
		{"1 + 2", sk1, sk2, sk3, nil},
		{"(n-1) + 2 wraps", skNm1, sk2, sk1, nil},
		{"tweak 0 is valid", sk2, sk0, sk2, nil},
		{"key 0", sk0, sk1, sk0, ErrInvalidSecKey},
		{"key n", skN, sk1, skN, ErrInvalidSecKey},
		{"key 2^256-1", skMax, sk1, skMax, ErrInvalidSecKey},
		{"tweak n", sk1, skN, sk1, ErrInvalidTweak},
		{"tweak 2^256-1", sk1, skMax, sk1, ErrInvalidTweak},
		{"1 + (n-1) is zero", sk1, skNm1, sk1, ErrZeroResult},
	})
}

func TestParityMultPrivateKeys(t *testing.T) {
	runScalarCases(t, MultPrivateKeys, ErrTweak, []scalarCase{
		{"2 * 3", sk2, sk3, sk6, nil},
		{"(n-1) * (n-1)", skNm1, skNm1, sk1, nil},
		{"key 0", sk0, sk2, sk0, ErrInvalidSecKey},
		{"key n", skN, sk2, skN, ErrInvalidSecKey},
		{"tweak 0 makes the key zero", sk2, sk0, sk2, ErrInvalidTweak},
		{"tweak n", sk2, skN, sk2, ErrInvalidTweak},
		{"tweak 2^256-1", sk2, skMax, sk2, ErrInvalidTweak},
	})
}

// PubKeyTweakMul is the package's ECDH: shared secret = b * A.
func TestParityPubKeyTweakMul(t *testing.T) {
	type tc struct {
		name  string
		pk    [33]byte
		tweak [32]byte
		want  [33]byte
		cause error
	}
	cases := []tc{
		{"3 * G", pointG, sk3, point3G, nil},
		{"(n-1) * G", pointG, skNm1, pointNG, nil},
		{"tweak 0 would give infinity", pointG, sk0, pointG, ErrInvalidTweak},
		{"tweak n", pointG, skN, pointG, ErrInvalidTweak},
		{"tweak 2^256-1", pointG, skMax, pointG, ErrInvalidTweak},
	}
	for name, bad := range badEncodings {
		cases = append(cases, tc{"invalid point " + name, bad, sk3, bad, ErrInvalidPubKey})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pk, tw := c.pk, c.tweak
			err := PubKeyTweakMul(&pk, &tw)
			if c.cause == nil {
				wantErr(t, err, nil)
			} else {
				wantErr(t, err, wrapErr(ErrPubKeyTweakMul, c.cause), ErrPubKeyTweakMul, c.cause)
			}
			if pk != c.want {
				t.Fatalf("result %x, want %x", pk, c.want)
			}
		})
	}
}

// TestNoIllegalCallback runs after the edge cases above (tests in a file run in source
// order, and this file sorts after abort_test.go): every argument is validated before
// libsecp256k1 sees it, so its illegal-argument callback must never have fired.
func TestNoIllegalCallback(t *testing.T) {
	if n := illegalCallbackCount(); n != 0 {
		t.Fatalf("libsecp256k1's illegal-argument callback fired %d times", n)
	}
}
