package sha3df

import (
	"crypto/sha3"
	"errors"
	"fmt"
)

// SumParallelHash128 applies the cSHAKE128 extendable output function to data
// in blocks of blockSize bytes, and returns an output of the given length in
// bytes.
// S is a customization byte string used for domain separation.
func SumParallelHash128(data []byte, blockSize, length int, S []byte) []byte {
	return sumParallelHash(NewParallelHash128(blockSize, S), data, length)
}

// SumParallelHash256 applies the cSHAKE256 extendable output function to data
// in blocks of blockSize bytes, and returns an output of the given length in
// bytes.
// S is a customization byte string used for domain separation.
func SumParallelHash256(data []byte, blockSize, length int, S []byte) []byte {
	return sumParallelHash(NewParallelHash256(blockSize, S), data, length)
}

// sumParallelHash applies the ParallelHash function to data and returns an
// output of the given length in bytes.
func sumParallelHash(ph *ParallelHash, data []byte, length int) []byte {
	blockSize := ph.BlockSize()
	for len(data) > 0 {
		var block []byte
		if len(data) < blockSize {
			block = data
			data = nil
		} else {
			block = data[:blockSize]
			data = data[blockSize:]
		}
		ph.WriteBlockHash(ph.SumBlock(block))
	}
	ph.Commit(length)

	out := make([]byte, length)
	ph.Read(out)
	return out
}

// ParallelHash is an instance of a ParallelHash function specified by the NIST
// SP 800-185 standard.
type ParallelHash struct {
	s             *sha3.SHAKE
	sum           func([]byte, int) []byte
	blockSize     int
	blockHashSize int
	blockCount    uint64
	committed     bool
}

// NewParallelHash128 creates a new ParallelHash128.
// blockSize is the block size in bytes for parallel hashing.
// S is a customization byte string used for domain separation.
func NewParallelHash128(blockSize int, S []byte) *ParallelHash {
	ph := &ParallelHash{
		s:             sha3.NewCSHAKE128([]byte("ParallelHash"), S),
		sum:           sha3.SumSHAKE128,
		blockSize:     blockSize,
		blockHashSize: 32,
	}
	ph.init()
	return ph
}

// NewParallelHash256 creates a new ParallelHash256.
// blockSize is the block size in bytes for parallel hashing.
// S is a customization byte string used for domain separation.
func NewParallelHash256(blockSize int, S []byte) *ParallelHash {
	ph := &ParallelHash{
		s:             sha3.NewCSHAKE256([]byte("ParallelHash"), S),
		sum:           sha3.SumSHAKE256,
		blockSize:     blockSize,
		blockHashSize: 64,
	}
	ph.init()
	return ph
}

// BlockSize returns the block size in bytes for parallel hashing.
func (ph *ParallelHash) BlockSize() int {
	return ph.blockSize
}

// Reset resets the ParallelHash to its initial state.
func (ph *ParallelHash) Reset() {
	ph.s.Reset()
	ph.blockCount = 0
	ph.committed = false
	ph.init()
}

// Commit finalizes the hash and prepares it for reading.
// Setting the length to 0 makes ParallelHash a ParallelHashXOR function with
// arbitrary-length output.
func (ph *ParallelHash) Commit(length int) error {
	if ph.committed {
		return errors.New("already committed")
	}
	ph.s.Write(rightEncode(uint64(ph.blockCount)))
	ph.s.Write(rightEncode(uint64(length) << 3))
	ph.committed = true
	return nil
}

// Read squeezes more output from the ParallelHash.
func (ph *ParallelHash) Read(p []byte) (n int, err error) {
	if !ph.committed {
		return 0, errors.New("not committed")
	}
	return ph.s.Read(p)
}

// SumBlock applies the cSHAKE extendable output function to a block of data and
// returns the hash of the block.
func (ph *ParallelHash) SumBlock(data []byte) []byte {
	return ph.sum(data, ph.blockHashSize)
}

// WriteBlockHash writes the hash of a block to the ParallelHash.
func (ph *ParallelHash) WriteBlockHash(h []byte) error {
	if ph.committed {
		return errors.New("already committed")
	}
	if len(h) != ph.blockHashSize {
		return fmt.Errorf("mismatch block hash size: got %d, want %d", len(h), ph.blockHashSize)
	}
	ph.s.Write(h)
	ph.blockCount++
	return nil
}

// WriteBlockHashes writes multiple block hashes to the ParallelHash.
func (ph *ParallelHash) WriteBlockHashes(hashes [][]byte) error {
	if ph.committed {
		return errors.New("already committed")
	}

	// check before writing
	for _, h := range hashes {
		if len(h) != ph.blockHashSize {
			return fmt.Errorf("mismatch block hash size: got %d, want %d", len(h), ph.blockHashSize)
		}
	}

	// write all hashes
	for _, h := range hashes {
		ph.s.Write(h)
	}
	ph.blockCount += uint64(len(hashes))
	return nil
}

// init initializes the ParallelHash instance
func (ph *ParallelHash) init() {
	ph.s.Write(leftEncode(uint64(ph.blockSize)))
}
