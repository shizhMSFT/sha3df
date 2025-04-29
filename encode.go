package sha3df

import (
	"encoding/binary"
	"math/bits"
)

// encodeLength returns the smallest positive integer for which 2^(8n) > x.
func encodeLength(x uint64) int {
	n := (bits.Len64(x) + 7) / 8
	if n == 0 {
		return 1
	}
	return n
}

// rightEncode encodes the integer x as a byte string in a way that can be
// unambiguously parsed from the end of the string by inserting the length of
// the byte string before the byte string representation of x.
func rightEncode(x uint64) []byte {
	n := encodeLength(x)
	encoded := make([]byte, 9)
	binary.BigEndian.PutUint64(encoded, x)
	encoded = encoded[8-n:]
	encoded[n] = byte(n)
	return encoded
}

// leftEncode encodes the integer x as a byte string in a way that can be
// unambiguously parsed from the beginning of the string by inserting the
// length of the byte string before the byte string representation of x.
func leftEncode(x uint64) []byte {
	n := encodeLength(x)
	encoded := make([]byte, 9)
	binary.BigEndian.PutUint64(encoded[1:], x)
	encoded = encoded[8-n:]
	encoded[0] = byte(n)
	return encoded
}
