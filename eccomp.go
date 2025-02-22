//go:build !libsecp256k1

package golibsecp256k1

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

func MultPrivateKeys(secKey1, secKey2 *[32]byte) error {
	key1 := new(big.Int).SetBytes(secKey1[:])
	key2 := new(big.Int).SetBytes(secKey2[:])

	curveParams := btcec.S256().Params()

	newKey := new(big.Int).Mul(key1, key2)
	newKey.Mod(newKey, curveParams.N)
	secKey1 = (*[32]byte)(newKey.Bytes())

	return nil
}
