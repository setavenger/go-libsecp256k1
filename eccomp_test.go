package golibsecp256k1

import (
	"crypto/rand"
	"testing"
)

// generateRandom32 returns a random 32-byte array.
func generateRandom32() [32]byte {
	var b [32]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic("failed to generate random bytes")
	}
	return b
}

func generateRandom33() [33]byte {
	var b [33]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic("failed to generate random bytes")
	}
	return b
}

func BenchmarkPubKeyAdd(b *testing.B) {
	// Generate two random 33-byte keys.
	key1 := generateRandom32()
	key2 := generateRandom32()

	pk1 := PubKeyFromSecKey(&key1)
	pk2 := PubKeyFromSecKey(&key2)

	// Reset the timer to ignore setup time.
	b.ResetTimer()
	var result [33]byte
	var err error
	for i := 0; i < b.N; i++ {
		result, err = PubKeyAdd(pk1, pk2)
		if err != nil {
			b.Fatal(err)
		}
		// Use the result to prevent compiler optimization
		_ = result[0]
	}
}

func BenchmarkPubKeyTweakMul(b *testing.B) {
	// Generate two random 33-byte keys.
	key1 := generateRandom32()
	key2 := generateRandom32()

	pk1 := PubKeyFromSecKey(&key1)

	// Reset the timer to ignore setup time.
	b.ResetTimer()
	var err error
	for i := 0; i < b.N; i++ {
		err = PubKeyTweakMul(pk1, &key2)
		if err != nil {
			b.Fatal(err)
		}
		// Use the result to prevent compiler optimization
		_ = pk1[0]
	}
}
