package sha3df

import "crypto/sha3"

// SumParallelHash128 applies the cSHAKE128 extendable output function to data
// in blocks of blockSize bytes, and returns an output of the given length in
// bytes.
// S is a customization byte string used for domain separation.
func SumParallelHash128(data []byte, blockSize, length int, S []byte) []byte {
	h := sha3.NewCSHAKE128([]byte("ParallelHash"), S)

	n := (len(data) + blockSize - 1) / blockSize
	h.Write(leftEncode(uint64(blockSize)))
	for range n {
		var blockHash []byte
		if len(data) < blockSize {
			blockHash = sha3.SumSHAKE128(data, 32)
		} else {
			blockHash = sha3.SumSHAKE128(data[:blockSize], 32)
			data = data[blockSize:]
		}
		h.Write(blockHash)
	}
	h.Write(rightEncode(uint64(n)))
	h.Write(rightEncode(uint64(length) << 3))

	out := make([]byte, length)
	h.Read(out)
	return out
}

// SumParallelHash256 applies the cSHAKE256 extendable output function to data
// in blocks of blockSize bytes, and returns an output of the given length in
// bytes.
// S is a customization byte string used for domain separation.
func SumParallelHash256(data []byte, blockSize, length int, S []byte) []byte {
	h := sha3.NewCSHAKE256([]byte("ParallelHash"), S)

	n := (len(data) + blockSize - 1) / blockSize
	h.Write(leftEncode(uint64(blockSize)))
	for range n {
		var blockHash []byte
		if len(data) < blockSize {
			blockHash = sha3.SumSHAKE256(data, 64)
		} else {
			blockHash = sha3.SumSHAKE256(data[:blockSize], 64)
			data = data[blockSize:]
		}
		h.Write(blockHash)
	}
	h.Write(rightEncode(uint64(n)))
	h.Write(rightEncode(uint64(length) << 3))

	out := make([]byte, length)
	h.Read(out)
	return out
}
