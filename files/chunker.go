package files

import (
	"fmt"
	"io"
)

func ReadChunks(name string, f io.Reader, chunkSize int, fileSize int64) func() (read []byte, hasNext bool, err error) {
	var alreadyRead int64

	return func() ([]byte, bool, error) {
		multipleChunksLeft := fileSize > alreadyRead+int64(chunkSize)
		toAlloc := chunkSize
		if !multipleChunksLeft {
			toAlloc = int(fileSize - alreadyRead)
		}
		if toAlloc == 0 {
			return nil, false, nil
		}
		read := make([]byte, toAlloc, chunkSize)
		n, err := io.ReadFull(f, read)
		if n != toAlloc || (err != nil && err != io.EOF) {
			return nil, false, fmt.Errorf("ReadChunks: could not read %v bytes from %v, read %v got error %v", toAlloc, name, n, err)
		}

		alreadyRead += int64(toAlloc)

		return read, multipleChunksLeft, nil
	}
}
