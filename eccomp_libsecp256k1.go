//go:build libsecp256k1

package golibsecp256k1

/*
#cgo CFLAGS: -I${SRCDIR}/libsecp256k1/include -I${SRCDIR}/libsecp256k1/src
#cgo CFLAGS: -DECMULT_GEN_PREC_BITS=4
#cgo CFLAGS: -DECMULT_WINDOW_SIZE=15
#cgo CFLAGS: -DENABLE_MODULE_SCHNORRSIG=1
#cgo CFLAGS: -DENABLE_MODULE_EXTRAKEYS=1

#include "./libsecp256k1/src/secp256k1.c"
#include "./libsecp256k1/src/precomputed_ecmult.c"
#include "./libsecp256k1/src/precomputed_ecmult_gen.c"
#include "./libsecp256k1/src/ecmult_gen.h"
#include "./libsecp256k1/src/ecmult.h"
#include "./libsecp256k1/src/modules/extrakeys/main_impl.h"
#include "./libsecp256k1/src/modules/schnorrsig/main_impl.h"

#include "./libsecp256k1/include/secp256k1.h"
#include "./libsecp256k1/include/secp256k1_extrakeys.h"
#include "./libsecp256k1/include/secp256k1_schnorrsig.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

var (
	// globalSecp256k1Context is our shared context for signing operations.
	globalSecp256k1Context *C.secp256k1_context
	// ErrTweak indicates a tweak operation failure.
	ErrTweak = errors.New("tweak operation failed")
)

func init() {
	globalSecp256k1Context = C.secp256k1_context_create(C.SECP256K1_CONTEXT_SIGN)
	if globalSecp256k1Context == nil {
		panic("failed to create secp256k1 context")
	}
}

// MultPrivateKeys multiplies a private key by a tweak value (in-place)
// using secp256k1_ec_privkey_tweak_mul.
func MultPrivateKeys(privKey, tweak *[32]byte) error {
	if C.secp256k1_ec_privkey_tweak_mul(
		globalSecp256k1Context,
		(*C.uchar)(unsafe.Pointer(&privKey[0])),
		(*C.uchar)(unsafe.Pointer(&tweak[0])),
	) != 1 {
		return ErrTweak
	}
	return nil
}

// PubKeyNegate negates a public key in compressed form (33 bytes).
// The pubkey is parsed, negated, then re-serialized in-place.
func PubKeyNegate(pubKey *[33]byte) error {
	var pk C.secp256k1_pubkey
	C.secp256k1_ec_pubkey_parse(
		globalSecp256k1Context,
		&pk,
		(*C.uchar)(unsafe.Pointer(&pubKey[0])),
		33,
	)
	C.secp256k1_ec_pubkey_negate(globalSecp256k1Context, &pk)

	var outLen C.size_t = 33
	C.secp256k1_ec_pubkey_serialize(
		globalSecp256k1Context,
		(*C.uchar)(unsafe.Pointer(pubKey)),
		&outLen,
		&pk,
		C.SECP256K1_EC_COMPRESSED,
	)

	return nil
}

// PubKeyAdd adds two public keys (both in compressed 33-byte form)
// and returns the resulting public key.
func PubKeyAdd(pubKey1, pubKey2 *[33]byte) ([33]byte, error) {
	var pk1, pk2 C.secp256k1_pubkey
	C.secp256k1_ec_pubkey_parse(
		globalSecp256k1Context,
		&pk1,
		(*C.uchar)(unsafe.Pointer(&pubKey1[0])),
		33,
	)
	C.secp256k1_ec_pubkey_parse(
		globalSecp256k1Context,
		&pk2,
		(*C.uchar)(unsafe.Pointer(&pubKey2[0])),
		33,
	)
	// Combine the two public keys.
	var outPk C.secp256k1_pubkey

	// Allocate a C array for 2 pointers.
	pks := C.malloc(2 * C.size_t(unsafe.Sizeof(uintptr(0))))
	defer C.free(pks)
	pksSlice := (*[2]*C.secp256k1_pubkey)(pks)
	pksSlice[0] = &pk1
	pksSlice[1] = &pk2

	C.secp256k1_ec_pubkey_combine(
		globalSecp256k1Context,
		&outPk,
		(**C.secp256k1_pubkey)(pks),
		2,
	)

	// var out [33]byte
	out := new([33]byte)
	var outLen C.size_t = 33
	C.secp256k1_ec_pubkey_serialize(
		globalSecp256k1Context,
		(*C.uchar)(unsafe.Pointer(out)),
		&outLen,
		&outPk,
		C.SECP256K1_EC_COMPRESSED,
	)

	return *out, nil
}

// SecKeyAdd adds a tweak value to a secret key in-place,
// using secp256k1_ec_privkey_tweak_add.
func SecKeyAdd(privKey, tweak *[32]byte) error {
	if C.secp256k1_ec_privkey_tweak_add(
		globalSecp256k1Context,
		(*C.uchar)(unsafe.Pointer(privKey)),
		(*C.uchar)(unsafe.Pointer(tweak)),
	) != 1 {
		return ErrTweak
	}
	return nil
}

// PubKeyFromSecKey creates a public key (compressed, 33 bytes)
// from the given secret key.
func PubKeyFromSecKey(privKey *[32]byte) *[33]byte {
	var pk C.secp256k1_pubkey
	C.secp256k1_ec_pubkey_create(
		globalSecp256k1Context,
		&pk,
		(*C.uchar)(unsafe.Pointer(&privKey[0])),
	)
	out := new([33]byte) // Allocate the array
	var outC [33]C.uchar
	var outLen C.size_t = 33
	C.secp256k1_ec_pubkey_serialize(
		globalSecp256k1Context,
		&outC[0],
		&outLen,
		&pk,
		C.SECP256K1_EC_COMPRESSED,
	)

	*out = *(*[33]byte)(unsafe.Pointer(&outC))

	return out
}

var ErrPubKeyTweakMul = errors.New("failed to tweak public key")

// PubKeyTweakMul multiplies a public key by a tweak (scalar) value.
// The public key is modified in-place.
func PubKeyTweakMul(pubKey *[33]byte, tweak *[32]byte) error {
	var pk C.secp256k1_pubkey
	code := C.secp256k1_ec_pubkey_parse(
		globalSecp256k1Context,
		&pk,
		(*C.uchar)(unsafe.Pointer(&pubKey[0])),
		33,
	)
	if code == 0 {
		return ErrPubKeyTweakMul
	}
	code = C.secp256k1_ec_pubkey_tweak_mul(
		globalSecp256k1Context,
		&pk,
		(*C.uchar)(unsafe.Pointer(&tweak[0])),
	)
	if code == 0 {
		return ErrPubKeyTweakMul
	}

	var outLen C.size_t = 33
	code = C.secp256k1_ec_pubkey_serialize(
		globalSecp256k1Context,
		(*C.uchar)(unsafe.Pointer(pubKey)),
		&outLen,
		&pk,
		C.SECP256K1_EC_COMPRESSED,
	)
	if code == 0 {
		return ErrPubKeyTweakMul
	}

	return nil
}
