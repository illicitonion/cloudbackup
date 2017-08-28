package main

import (
	"bytes"
	"crypto/aes"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/illicitonion/cloudbackup/meta"
)

func TestEncryptUploads(t *testing.T) {
	chunkStore := &recordingChunkStore{}
	db := makeDB(t)
	do(t, db, chunkStore, "01234567890123456", true, 0x01)
	want := map[string][]byte{
		"500002b7d895d882170ea0823388708be81ca5f5f64f2c358e6cb7ee7ca16e37": []byte{
			0x09, 0xB3, 0x76, 0x13, 0x6D, 0x0B, 0xF6, 0x2E,
			0xD6, 0xD0, 0x1C, 0x73, 0xE7, 0xF3, 0xD3, 0x99,
		},
		"bfda79581f572a70cd481efb63ef6f07e52f3e45afb21ca35a452a3e49e77e4b": []byte{
			0x87, 0x6B, 0x7D, 0xE4, 0xE8, 0xFF, 0xD0, 0x59,
			0xF0, 0x79, 0x30, 0x9E, 0xC1, 0xE9, 0x8C, 0xC0,
		},
	}
	if !reflect.DeepEqual(want, chunkStore.saves) {
		t.Errorf("saves: want %v got %v", want, chunkStore.saves)
	}
}

func TestEncryptNoChangeUpload(t *testing.T) {
	chunkStore := &recordingChunkStore{}
	db := makeDB(t)
	do(t, db, chunkStore, "01234567890123456", true, 0x01)
	chunkStore.Reset()
	do(t, db, chunkStore, "11234567890123456", true, 0x02)
	want := map[string][]byte{
		"cd6ebe78f3a66a4db47e8c8a704970b341192f8d9f4035ee9c63455f9915c644": []byte{
			0xA2, 0xF8, 0x17, 0x63, 0x1C, 0x54, 0x34, 0xAC,
			0xDB, 0x20, 0x87, 0x4E, 0xC2, 0xAD, 0x18, 0x21,
		},
		"3016e83f0931efa1ffff6529af142588dbe5dc63968693ad1fe0ee8452adb1cc": []byte{
			0xDF, 0x1D, 0x67, 0xA3, 0x5C, 0xD2, 0x2F, 0xEE,
			0x75, 0x18, 0x44, 0x0B, 0x15, 0x10, 0x4A, 0xA4,
		},
	}
	if !reflect.DeepEqual(want, chunkStore.saves) {
		t.Errorf("saves: want %v got % X", want, chunkStore.saves)
	}
}

func TestEncryptNoChangeNoUpload(t *testing.T) {
	chunkStore := &recordingChunkStore{}
	db := makeDB(t)
	do(t, db, chunkStore, "01234567890123456", false, 0x01)
	chunkStore.Reset()
	do(t, db, chunkStore, "01234567890123456", false, 0x02)
	want := map[string][]byte{}
	if !reflect.DeepEqual(want, chunkStore.saves) {
		t.Errorf("saves: want %v got %v", want, chunkStore.saves)
	}
}

func makeDB(t *testing.T) *meta.DB {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := f.Name()
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := meta.NewDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func do(t *testing.T, db *meta.DB, chunkStore chunkStoreInterface, v string, uploadIfUnchanged bool, ivByte byte) {
	makeIV := func() ([]byte, error) {
		return bytes.Repeat([]byte{ivByte}, aes.BlockSize), nil
	}

	path := "filename"
	chunks, err := encryptFile(bytes.Repeat([]byte{0x02}, 32), bytes.Repeat([]byte{0x03}, 32), makeIV, db, chunkStore, 16, path, bytes.NewBufferString(v), int64(len(v)), uploadIfUnchanged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Put(path, &meta.Entry{
		Bytes:  int64(len(v)),
		Chunks: chunks,
		Mode:   0777,
		User:   "",
		Group:  "",
	}); err != nil {
		t.Fatal(err)
	}
}

type recordingChunkStore struct {
	saves map[string][]byte
}

func (s *recordingChunkStore) Save(hmac string, contents []byte) error {
	if s.saves == nil {
		s.Reset()
	}
	s.saves[hmac] = contents
	return nil
}

func (s *recordingChunkStore) Read(hmac string) ([]byte, error) {
	return nil, nil
}

func (s *recordingChunkStore) Reset() {
	s.saves = make(map[string][]byte)
}
