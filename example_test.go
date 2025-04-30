package sha3df_test

import (
	"fmt"
	"sync"

	"github.com/shizhMSFT/sha3df"
)

func ExampleParallelHash() {
	// Create a new ParallelHash instance with the desired block size
	blockSize := 8
	ph := sha3df.NewParallelHash256(blockSize, nil)

	// Prepare the data to be hashed
	data := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	}
	blockCount := (len(data) + blockSize - 1) / blockSize

	// Parallel hashing individual blocks with multiple goroutines
	blockHashes := make([][]byte, blockCount)
	var wg sync.WaitGroup
	for i := range blockCount {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var block []byte
			if i == blockCount-1 {
				block = data[i*blockSize:]
			} else {
				block = data[i*blockSize : (i+1)*blockSize]
			}
			blockHashes[i] = ph.SumBlock(block)
		}(i)
	}
	wg.Wait()

	// Commit the hashes and retrieve the final hash
	ph.WriteBlockHashes(blockHashes)
	hash := make([]byte, 64)
	ph.Commit(len(hash))
	ph.Read(hash)

	// Print the final hash
	fmt.Printf("%x", hash)
	// Output:
	// bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c451105531b7f2a3e0ce055c02805e7c2de1fb746af97a1dd01f43b824e31b87612410429
}
