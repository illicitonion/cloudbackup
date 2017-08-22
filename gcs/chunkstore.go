package gcs

import (
	"context"
	"io"
	"os"

	"cloud.google.com/go/storage"
)

type ChunkStore struct {
	Bucket                   *storage.BucketHandle
	OptimizeForRepeatedSaves bool
}

func (b *ChunkStore) Read(hmac string) ([]byte, error) {
	object := b.Bucket.Object(hmac)
	reader, err := object.NewReader(context.Background())
	if err != nil {
		if err == storage.ErrObjectNotExist {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	defer reader.Close()

	contents := make([]byte, reader.Size())
	_, err = io.ReadFull(reader, contents)
	return contents, err
}

func (b *ChunkStore) Save(hmac string, contents []byte) error {
	object := b.Bucket.Object(hmac)
	if b.OptimizeForRepeatedSaves {
		object = object.If(storage.Conditions{
			DoesNotExist: true,
		})
	}
	writer := object.NewWriter(context.Background())
	_, err := writer.Write(contents)
	if err != nil {
		writer.Close()
		return err
	}
	return writer.Close()
}
