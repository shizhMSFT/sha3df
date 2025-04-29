package sha3df

import "crypto/sha3"

func SumParallelHash128(data []byte, blockSize, length int) []byte {
	h := sha3.NewCSHAKE128([]byte("ParallelHash"), nil)

	n := (len(data) + blockSize - 1) / blockSize
	h.Write(leftEncode(uint64(blockSize)))
	for i := 0; i < n; i++ {
		h.Write(sha3.SumSHAKE128(data[:blockSize], 32))
		data = data[blockSize:]
	}
	h.Write(rightEncode(uint64(n)))
	h.Write(rightEncode(uint64(length)))

	out := make([]byte, length)
	h.Read(out)
	return out
}

func SumParallelHash256(data []byte, blockSize, length int) []byte {
	h := sha3.NewCSHAKE256([]byte("ParallelHash"), nil)

	n := (len(data) + blockSize - 1) / blockSize
	h.Write(leftEncode(uint64(blockSize)))
	for i := 0; i < n; i++ {
		h.Write(sha3.SumSHAKE256(data[:blockSize], 64))
		data = data[blockSize:]
	}
	h.Write(rightEncode(uint64(n)))
	h.Write(rightEncode(uint64(length)))

	out := make([]byte, length)
	h.Read(out)
	return out
}
