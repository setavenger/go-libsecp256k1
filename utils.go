package golibsecp256k1

import "fmt"

func ConvertToFixedLength32(input []byte) [32]byte {
	if len(input) != 32 {
		panic(fmt.Sprintf("wrong length expected 32 got %d", len(input)))
	}
	var output [32]byte
	copy(output[:], input)
	return output
}

func ConvertToFixedLength33(input []byte) [33]byte {
	if len(input) != 33 {
		panic(fmt.Sprintf("wrong length expected 33 got %d", len(input)))
	}
	var output [33]byte
	copy(output[:], input)
	return output
}
