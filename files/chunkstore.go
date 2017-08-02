package files

import (
	"io/ioutil"
	"path/filepath"
)

type ChunkStore struct {
	RootDirectory string
}

func (b *ChunkStore) Read(hmac string) ([]byte, error) {
	return ioutil.ReadFile(filepath.Join(b.RootDirectory, hmac))
}

func (b *ChunkStore) Save(hmac string, contents []byte) error {
	return ioutil.WriteFile(filepath.Join(b.RootDirectory, hmac), contents, 0600)
}
