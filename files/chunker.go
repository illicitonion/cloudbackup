package files

import (
	"fmt"
	"io"
	"os"
)

func ReadChunks(file *os.File, chunkSize int) func() (read []byte, hasNext bool, err error) {
	fi, err := file.Stat()
	if err != nil {
		return func() ([]byte, bool, error) { return nil, false, err }
	}

	var alreadyRead int64

	return func() ([]byte, bool, error) {
		multipleChunksLeft := fi.Size() > alreadyRead+int64(chunkSize)
		toAlloc := chunkSize
		if !multipleChunksLeft {
			toAlloc = int(fi.Size() - alreadyRead)
		}
		if toAlloc == 0 {
			return nil, false, nil
		}
		read := make([]byte, toAlloc, chunkSize)
		n, err := io.ReadFull(file, read)
		if n != toAlloc || (err != nil && err != io.EOF) {
			return nil, false, fmt.Errorf("ReadChunks: could not read %v bytes from %v, read %v got error %v", toAlloc, fi.Name(), n, err)
		}

		alreadyRead += int64(toAlloc)

		return read, multipleChunksLeft, nil
	}
}
