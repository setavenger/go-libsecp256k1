//go:build !libsecp256k1

// Package golibsecp256k1 includes CGO code of the very performant libsecp256k1 libary for Bitcoin Core.
// Per default it uses pure Go code with btcec/v2.
package golibsecp256k1

import (
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

var (
	// ErrTweak indicates a tweak operation failure.
	ErrTweak = errors.New("tweak operation failed")
)

// MultPrivateKeys multiplies a private key by a tweak value (in-place)
// i.e., privKey = privKey * tweak mod N.
func MultPrivateKeys(privKey, tweak *[32]byte) error {
	curve := btcec.S256()
	key := new(big.Int).SetBytes(privKey[:])
	t := new(big.Int).SetBytes(tweak[:])
	key.Mul(key, t)
	key.Mod(key, curve.Params().N)
	if key.Sign() == 0 {
		return ErrTweak
	}
	b := key.Bytes()
	var res [32]byte
	// Left-pad with zeros if needed.
	copy(res[32-len(b):], b)
	*privKey = res
	return nil
}

// PubKeyNegate negates a public key in compressed form (33 bytes).
// It parses the public key, negates it (i.e. computes (x, -y mod p)),
// then re-serializes it in-place.
func PubKeyNegate(pubKey *[33]byte) error {
	pk, err := btcec.ParsePubKey(pubKey[:])
	if err != nil {
		return err
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
// and returns the resulting public key.
func PubKeyAdd(pubKey1, pubKey2 *[33]byte) ([33]byte, error) {
	var result [33]byte
	p1, err := btcec.ParsePubKey(pubKey1[:])
	if err != nil {
		return result, err
	}
	p2, err := btcec.ParsePubKey(pubKey2[:])
	if err != nil {
		return result, err
	}
	curve := btcec.S256()
	x, y := curve.Add(p1.X(), p1.Y(), p2.X(), p2.Y())
	if x == nil || y == nil {
		return result, errors.New("point addition failed")
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
// i.e., privKey = privKey + tweak mod N.
func SecKeyAdd(privKey, tweak *[32]byte) error {
	curve := btcec.S256()
	key := new(big.Int).SetBytes(privKey[:])
	t := new(big.Int).SetBytes(tweak[:])
	key.Add(key, t)
	key.Mod(key, curve.Params().N)
	if key.Sign() == 0 {
		return ErrTweak
	}
	b := key.Bytes()
	var res [32]byte
	copy(res[32-len(b):], b)
	*privKey = res
	return nil
}

// PubKeyFromSecKey creates a public key (compressed, 33 bytes)
// from the given secret key.
func PubKeyFromSecKey(privKey *[32]byte) *[33]byte {
	_, pub := btcec.PrivKeyFromBytes(privKey[:])
	serialized := pub.SerializeCompressed()
	var result [33]byte
	copy(result[:], serialized)
	return &result
}

// PubKeyTweakMul multiplies a public key by a tweak (scalar) value.
// The public key is modified in-place, i.e., pubKey = pubKey * tweak.
func PubKeyTweakMul(pubKey *[33]byte, tweak *[32]byte) error {
	p, err := btcec.ParsePubKey(pubKey[:])
	if err != nil {
		return err
	}
	t := new(big.Int).SetBytes(tweak[:])
	curve := btcec.S256()
	x, y := curve.ScalarMult(p.X(), p.Y(), t.Bytes())
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
