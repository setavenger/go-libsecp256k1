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

func BenchmarkMulUint256ModN(b *testing.B) {
	a := generateRandom32()
	c := generateRandom32()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MulUint256ModN(a, c)
	}
}

func BenchmarkMultPrivateKeys(b *testing.B) {
	// Generate two random 32-byte keys.
	key1 := generateRandom32()
	key2 := generateRandom32()

	// Reset the timer to ignore setup time.
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// _, _ = MultPrivateKeys(key1, key2)
		_ = MultPrivateKeys(&key1, &key2)
	}
}

func BenchmarkAddUint256(b *testing.B) {
	// Generate two random 32-byte numbers.
	a := generateRandom32()
	c := generateRandom32()

	// Reset the timer to ignore setup time.
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = addUint256(a, c)
	}
}
