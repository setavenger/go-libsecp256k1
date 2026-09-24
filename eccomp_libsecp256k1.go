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

#include <string.h>

// Every operation runs as one C helper that checks each libsecp256k1 return code and
// never passes an unparsed or failed struct onward. Outputs are written only on success.
enum {
	GLS_OK = 0,
	GLS_INVALID_PUBKEY = 1,
	GLS_INFINITY = 2,
	GLS_INVALID_SECKEY = 3,
	GLS_INVALID_TWEAK = 4,
	GLS_ZERO_RESULT = 5,
	GLS_INTERNAL = 6
};

// The default illegal-argument callback aborts the process. The helpers below validate
// every argument first, so it can only fire on a bug in this file; the replacement
// counts the call and returns, and the libsecp256k1 function then returns 0, which the
// helper reports as an error instead of the process dying.
static long gls_illegal_calls = 0;

static void gls_illegal_callback(const char *msg, void *data) {
	(void)msg;
	(void)data;
	__atomic_fetch_add(&gls_illegal_calls, 1, __ATOMIC_RELAXED);
}

static long gls_illegal_count(void) {
	return __atomic_load_n(&gls_illegal_calls, __ATOMIC_RELAXED);
}

static secp256k1_context *gls_context_create(void) {
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	if (ctx != NULL) {
		secp256k1_context_set_illegal_callback(ctx, gls_illegal_callback, NULL);
	}
	return ctx;
}

static int gls_serialize(const secp256k1_context *ctx, unsigned char *out33, const secp256k1_pubkey *pk) {
	unsigned char buf[33];
	size_t len = sizeof(buf);
	if (!secp256k1_ec_pubkey_serialize(ctx, buf, &len, pk, SECP256K1_EC_COMPRESSED) || len != 33) {
		return GLS_INTERNAL;
	}
	memcpy(out33, buf, 33);
	return GLS_OK;
}

static int gls_pubkey_add(const secp256k1_context *ctx, unsigned char *out33,
                          const unsigned char *a33, const unsigned char *b33) {
	secp256k1_pubkey a, b, sum;
	const secp256k1_pubkey *ins[2];
	if (!secp256k1_ec_pubkey_parse(ctx, &a, a33, 33)) return GLS_INVALID_PUBKEY;
	if (!secp256k1_ec_pubkey_parse(ctx, &b, b33, 33)) return GLS_INVALID_PUBKEY;
	ins[0] = &a;
	ins[1] = &b;
	// With two valid inputs, combine fails only when the sum is the point at infinity.
	if (!secp256k1_ec_pubkey_combine(ctx, &sum, ins, 2)) return GLS_INFINITY;
	return gls_serialize(ctx, out33, &sum);
}

static int gls_pubkey_negate(const secp256k1_context *ctx, unsigned char *inout33) {
	secp256k1_pubkey pk;
	if (!secp256k1_ec_pubkey_parse(ctx, &pk, inout33, 33)) return GLS_INVALID_PUBKEY;
	if (!secp256k1_ec_pubkey_negate(ctx, &pk)) return GLS_INTERNAL;
	return gls_serialize(ctx, inout33, &pk);
}

static int gls_pubkey_create(const secp256k1_context *ctx, unsigned char *out33, const unsigned char *sk32) {
	secp256k1_pubkey pk;
	if (!secp256k1_ec_seckey_verify(ctx, sk32)) return GLS_INVALID_SECKEY;
	if (!secp256k1_ec_pubkey_create(ctx, &pk, sk32)) return GLS_INVALID_SECKEY;
	return gls_serialize(ctx, out33, &pk);
}

static int gls_pubkey_tweak_mul(const secp256k1_context *ctx, unsigned char *inout33, const unsigned char *tweak32) {
	secp256k1_pubkey pk;
	if (!secp256k1_ec_pubkey_parse(ctx, &pk, inout33, 33)) return GLS_INVALID_PUBKEY;
	// The pubkey is valid, so a failure here means the tweak is zero or >= n.
	if (!secp256k1_ec_pubkey_tweak_mul(ctx, &pk, tweak32)) return GLS_INVALID_TWEAK;
	return gls_serialize(ctx, inout33, &pk);
}

static int gls_is_zero32(const unsigned char *b32) {
	unsigned char acc = 0;
	int i;
	for (i = 0; i < 32; i++) acc |= b32[i];
	return acc == 0;
}

static int gls_seckey_tweak_add(const secp256k1_context *ctx, unsigned char *sk32, const unsigned char *tweak32) {
	unsigned char tmp[32];
	if (!secp256k1_ec_seckey_verify(ctx, sk32)) return GLS_INVALID_SECKEY;
	// A zero tweak is valid for addition; any other tweak that fails verification is >= n.
	if (!gls_is_zero32(tweak32) && !secp256k1_ec_seckey_verify(ctx, tweak32)) return GLS_INVALID_TWEAK;
	memcpy(tmp, sk32, 32);
	// Both inputs are valid, so a failure means the sum is zero; libsecp256k1 zeroes tmp
	// then, which is why the caller's key is only overwritten on success.
	if (!secp256k1_ec_seckey_tweak_add(ctx, tmp, tweak32)) return GLS_ZERO_RESULT;
	memcpy(sk32, tmp, 32);
	return GLS_OK;
}

static int gls_seckey_tweak_mul(const secp256k1_context *ctx, unsigned char *sk32, const unsigned char *tweak32) {
	unsigned char tmp[32];
	if (!secp256k1_ec_seckey_verify(ctx, sk32)) return GLS_INVALID_SECKEY;
	if (!secp256k1_ec_seckey_verify(ctx, tweak32)) return GLS_INVALID_TWEAK;
	memcpy(tmp, sk32, 32);
	if (!secp256k1_ec_seckey_tweak_mul(ctx, tmp, tweak32)) return GLS_INTERNAL;
	memcpy(sk32, tmp, 32);
	return GLS_OK;
}
*/
import "C"
import (
	"errors"
	"unsafe"
)

// globalSecp256k1Context is the shared, read-only context. It is created once and never
// mutated afterwards, so it is safe for concurrent use.
var globalSecp256k1Context *C.secp256k1_context

// errInternal reports a libsecp256k1 failure that validated inputs cannot cause.
var errInternal = errors.New("golibsecp256k1: unexpected libsecp256k1 failure")

func init() {
	globalSecp256k1Context = C.gls_context_create()
	if globalSecp256k1Context == nil {
		panic("failed to create secp256k1 context")
	}
}

// codeErr maps a helper's return code to the backend-independent error.
func codeErr(code C.int) error {
	switch code {
	case C.GLS_OK:
		return nil
	case C.GLS_INVALID_PUBKEY:
		return ErrInvalidPubKey
	case C.GLS_INFINITY:
		return ErrPointAtInfinity
	case C.GLS_INVALID_SECKEY:
		return ErrInvalidSecKey
	case C.GLS_INVALID_TWEAK:
		return ErrInvalidTweak
	case C.GLS_ZERO_RESULT:
		return ErrZeroResult
	default:
		return errInternal
	}
}

// illegalCallbackCount reports how often libsecp256k1's illegal-argument callback fired.
func illegalCallbackCount() int64 { return int64(C.gls_illegal_count()) }

func uc(p unsafe.Pointer) *C.uchar { return (*C.uchar)(p) }

// MultPrivateKeys multiplies a private key by a tweak value (in-place)
// i.e., privKey = privKey * tweak mod N. The key must be in [1, n-1] and the tweak in
// [1, n-1]; on error the key is left unchanged.
// todo: rename to MultSecKey?
func MultPrivateKeys(secKey, tweak *[32]byte) error {
	code := C.gls_seckey_tweak_mul(globalSecp256k1Context, uc(unsafe.Pointer(secKey)), uc(unsafe.Pointer(tweak)))
	if err := codeErr(code); err != nil {
		return wrapErr(ErrTweak, err)
	}
	return nil
}

// PubKeyNegate negates a public key in compressed form (33 bytes), in-place.
// It returns ErrInvalidPubKey, leaving the input unchanged, if it is not a valid point.
func PubKeyNegate(pubKey *[33]byte) error {
	return codeErr(C.gls_pubkey_negate(globalSecp256k1Context, uc(unsafe.Pointer(pubKey))))
}

// PubKeyAdd adds two public keys (both in compressed 33-byte form)
// and returns the resulting public key. It returns ErrInvalidPubKey if either input is
// not a valid point and ErrPointAtInfinity if the sum is the point at infinity.
func PubKeyAdd(pubKey1, pubKey2 *[33]byte) ([33]byte, error) {
	var out [33]byte
	code := C.gls_pubkey_add(globalSecp256k1Context,
		uc(unsafe.Pointer(&out)), uc(unsafe.Pointer(pubKey1)), uc(unsafe.Pointer(pubKey2)))
	if err := codeErr(code); err != nil {
		return [33]byte{}, err
	}
	return out, nil
}

// SecKeyAdd adds a tweak value to a secret key in-place,
// i.e., privKey = privKey + tweak mod N. The key must be in [1, n-1] and the tweak in
// [0, n-1]; on error the key is left unchanged.
func SecKeyAdd(secKey, tweak *[32]byte) error {
	code := C.gls_seckey_tweak_add(globalSecp256k1Context, uc(unsafe.Pointer(secKey)), uc(unsafe.Pointer(tweak)))
	if err := codeErr(code); err != nil {
		return wrapErr(ErrTweak, err)
	}
	return nil
}

// PubKeyFromSecKeyChecked returns the compressed public key of secKey, or
// ErrInvalidSecKey if secKey is zero or not below the group order.
func PubKeyFromSecKeyChecked(secKey *[32]byte) ([33]byte, error) {
	var out [33]byte
	code := C.gls_pubkey_create(globalSecp256k1Context, uc(unsafe.Pointer(&out)), uc(unsafe.Pointer(secKey)))
	if err := codeErr(code); err != nil {
		return [33]byte{}, err
	}
	return out, nil
}

// PubKeyFromSecKey creates a public key (compressed, 33 bytes)
// from the given secret key. It returns nil if the secret key is invalid (zero or not
// below the group order); use PubKeyFromSecKeyChecked to get the error instead.
func PubKeyFromSecKey(secKey *[32]byte) *[33]byte {
	out, err := PubKeyFromSecKeyChecked(secKey)
	if err != nil {
		return nil
	}
	return &out
}

// PubKeyTweakMul multiplies a public key by a tweak (scalar) value, in-place.
// The tweak must be in [1, n-1]; on error the key is left unchanged.
func PubKeyTweakMul(pubKey *[33]byte, tweak *[32]byte) error {
	code := C.gls_pubkey_tweak_mul(globalSecp256k1Context, uc(unsafe.Pointer(pubKey)), uc(unsafe.Pointer(tweak)))
	if err := codeErr(code); err != nil {
		return wrapErr(ErrPubKeyTweakMul, err)
	}
	return nil
}
