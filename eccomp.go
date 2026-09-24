//go:build !libsecp256k1

// Package golibsecp256k1 includes CGO code of the very performant libsecp256k1 libary for Bitcoin Core.
// Per default it uses pure Go code with btcec/v2.
package golibsecp256k1

import (
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

// scalar parses b as a scalar mod n. It reports whether b is zero and whether b is not
// below the group order n (in which case the scalar is b - n and must be rejected).
func scalar(b *[32]byte) (s btcec.ModNScalar, zero, overflow bool) {
	overflow = s.SetBytes(b) != 0
	return s, !overflow && s.IsZero(), overflow
}

// secKeyScalar parses a secret key, which must be in [1, n-1] as libsecp256k1 requires.
func secKeyScalar(b *[32]byte) (btcec.ModNScalar, error) {
	s, zero, overflow := scalar(b)
	if zero || overflow {
		return s, ErrInvalidSecKey
	}
	return s, nil
}

// MultPrivateKeys multiplies a private key by a tweak value (in-place)
// i.e., privKey = privKey * tweak mod N. The key must be in [1, n-1] and the tweak in
// [1, n-1]; on error the key is left unchanged.
func MultPrivateKeys(privKey, tweak *[32]byte) error {
	key, err := secKeyScalar(privKey)
	if err != nil {
		return wrapErr(ErrTweak, err)
	}
	t, zero, overflow := scalar(tweak)
	if zero || overflow {
		return wrapErr(ErrTweak, ErrInvalidTweak)
	}
	key.Mul(&t)
	// n is prime and both factors are non-zero, so the product cannot be zero.
	*privKey = key.Bytes()
	return nil
}

// PubKeyNegate negates a public key in compressed form (33 bytes).
// It parses the public key, negates it (i.e. computes (x, -y mod p)),
// then re-serializes it in-place.
// It returns ErrInvalidPubKey, leaving the input unchanged, if it is not a valid point.
func PubKeyNegate(pubKey *[33]byte) error {
	pk, err := btcec.ParsePubKey(pubKey[:])
	if err != nil {
		return ErrInvalidPubKey
	}
	curve := btcec.S256()
	newY := new(big.Int).Neg(pk.Y())
	newY.Mod(newY, curve.Params().P)

	negated, err := convertPointsToPublicKey(pk.X(), newY)
	if err != nil {
		return err
	}

	serialized := negated.SerializeCompressed()
	if len(serialized) != 33 {
		return errors.New("unexpected public key length")
	}

	copy(pubKey[:], serialized)

	return nil
}

// PubKeyAdd adds two public keys (both in compressed 33-byte form)
// and returns the resulting public key. It returns ErrInvalidPubKey if either input is
// not a valid point and ErrPointAtInfinity if the sum is the point at infinity.
func PubKeyAdd(pubKey1, pubKey2 *[33]byte) ([33]byte, error) {
	var result [33]byte
	p1, err := btcec.ParsePubKey(pubKey1[:])
	if err != nil {
		return result, ErrInvalidPubKey
	}
	p2, err := btcec.ParsePubKey(pubKey2[:])
	if err != nil {
		return result, ErrInvalidPubKey
	}
	curve := btcec.S256()
	x, y := curve.Add(p1.X(), p1.Y(), p2.X(), p2.Y())
	if x == nil || y == nil {
		return result, errors.New("point addition failed")
	}
	// The affine Add reports the point at infinity as (0, 0).
	if x.Sign() == 0 && y.Sign() == 0 {
		return result, ErrPointAtInfinity
	}
	pub, err := convertPointsToPublicKey(x, y)
	if err != nil {
		return result, err
	}

	serialized := pub.SerializeCompressed()
	if len(serialized) != 33 {
		return result, errors.New("unexpected public key length")
	}
	copy(result[:], serialized)
	return result, nil
}

// SecKeyAdd adds a tweak value to a secret key in-place,
// i.e., privKey = privKey + tweak mod N. The key must be in [1, n-1] and the tweak in
// [0, n-1]; on error the key is left unchanged.
func SecKeyAdd(privKey, tweak *[32]byte) error {
	key, err := secKeyScalar(privKey)
	if err != nil {
		return wrapErr(ErrTweak, err)
	}
	t, _, overflow := scalar(tweak)
	if overflow {
		return wrapErr(ErrTweak, ErrInvalidTweak)
	}
	key.Add(&t)
	if key.IsZero() {
		return wrapErr(ErrTweak, ErrZeroResult)
	}
	*privKey = key.Bytes()
	return nil
}

// PubKeyFromSecKeyChecked returns the compressed public key of privKey, or
// ErrInvalidSecKey if privKey is zero or not below the group order.
func PubKeyFromSecKeyChecked(privKey *[32]byte) ([33]byte, error) {
	var result [33]byte
	if _, err := secKeyScalar(privKey); err != nil {
		return result, err
	}
	_, pub := btcec.PrivKeyFromBytes(privKey[:])
	copy(result[:], pub.SerializeCompressed())
	return result, nil
}

// PubKeyFromSecKey creates a public key (compressed, 33 bytes)
// from the given secret key. It returns nil if the secret key is invalid (zero or not
// below the group order); use PubKeyFromSecKeyChecked to get the error instead.
func PubKeyFromSecKey(privKey *[32]byte) *[33]byte {
	result, err := PubKeyFromSecKeyChecked(privKey)
	if err != nil {
		return nil
	}
	return &result
}

// PubKeyTweakMul multiplies a public key by a tweak (scalar) value.
// The public key is modified in-place, i.e., pubKey = pubKey * tweak.
// The tweak must be in [1, n-1]; on error the key is left unchanged.
func PubKeyTweakMul(pubKey *[33]byte, tweak *[32]byte) error {
	p, err := btcec.ParsePubKey(pubKey[:])
	if err != nil {
		return wrapErr(ErrPubKeyTweakMul, ErrInvalidPubKey)
	}
	if _, zero, overflow := scalar(tweak); zero || overflow {
		return wrapErr(ErrPubKeyTweakMul, ErrInvalidTweak)
	}
	curve := btcec.S256()
	x, y := curve.ScalarMult(p.X(), p.Y(), tweak[:])
	if x == nil || y == nil {
		return errors.New("scalar multiplication failed")
	}

	newPub, err := convertPointsToPublicKey(x, y)
	if err != nil {
		return err
	}

	serialized := newPub.SerializeCompressed()
	if len(serialized) != 33 {
		return errors.New("unexpected public key length")
	}
	copy(pubKey[:], serialized)
	return nil
}

func convertPointsToPublicKey(x, y *big.Int) (*btcec.PublicKey, error) {
	pubkeyBytes := make([]byte, 65)
	pubkeyBytes[0] = 0x04
	x.FillBytes(pubkeyBytes[1:33])
	y.FillBytes(pubkeyBytes[33:])

	finalPubKey, err := btcec.ParsePubKey(pubkeyBytes)
	if err != nil {
		return nil, err
	}

	return finalPubKey, nil
}

// illegalCallbackCount mirrors the cgo backend's counter; pure Go has no such callback.
func illegalCallbackCount() int64 { return 0 }
