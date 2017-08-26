package meta

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/boltdb/bolt"
)

type Entry struct {
	Bytes  int64
	Chunks []Chunk
	Mode   os.FileMode
	User   string
	Group  string
}

type Chunk struct {
	IV            []byte
	CiphertextMAC []byte
}

func NewDB(path string) (*DB, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}
	return &DB{db}, nil
}

type DB struct {
	db *bolt.DB
}

var root = []byte{'.'}

func (d *DB) Put(path string, entry *Entry) ([]string, error) {
	buf, err := EncodeEntry(entry)
	if err != nil {
		return nil, fmt.Errorf("meta: error encoding entry for path %q: %v", path, err)
	}

	createdBuckets := make([]string, 0)

	return createdBuckets, d.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(root)
		if err != nil {
			return fmt.Errorf("meta: creating/getting root bucket: %v", err)
		}
		parts := strings.Split(path, "/")
		last := len(parts) - 1

		for i, part := range parts[:last] {
			child := bucket.Bucket([]byte(part))
			if child != nil {
				bucket = child
			} else {
				bucket, err = bucket.CreateBucket([]byte(part))
				bucketPath := strings.Join(parts[:i+1], "/")
				if err != nil {
					return fmt.Errorf("meta: creating/getting bucket %v: %v", bucketPath, err)
				}
				createdBuckets = append(createdBuckets, bucketPath)
			}
		}
		return bucket.Put([]byte(parts[last]), buf)
	})
}

func (d *DB) Get(path string) (entries map[string]Entry, err error) {
	entries = make(map[string]Entry)

	err = d.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(root)
		if bucket == nil {
			return fmt.Errorf("meta: no root bucket")
		}
		parts := strings.Split(path, "/")
		last := len(parts) - 1
		for i, part := range parts[:last] {
			bucket = bucket.Bucket([]byte(part))
			bucketPath := strings.Join(parts[:i+1], "/")
			if bucket == nil {
				return fmt.Errorf("meta: no bucket %v", bucketPath)
			}
			v := bucket.Get(root)
			if v != nil {
				entry, err := DecodeEntry(v)
				if err != nil {
					return err
				}
				entries[bucketPath] = *entry
			}
		}

		v := bucket.Get([]byte(parts[last]))
		if v != nil {
			entry, err := DecodeEntry(v)
			if err != nil {
				return err
			}
			entries[path] = *entry
			return nil
		}

		var toVisit []namedBucket

		if path == string(root) {
			toVisit = []namedBucket{
				namedBucket{
					"",
					bucket,
				},
			}
		} else {
			bucket = bucket.Bucket([]byte(parts[last]))
			if bucket == nil {
				return fmt.Errorf("meta: could not find file %q", path)
			}
			toVisit = []namedBucket{
				namedBucket{
					path + "/",
					bucket,
				},
			}
		}

		visit := func(b namedBucket) error {
			cursor := b.Bucket.Cursor()
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				if reflect.DeepEqual(k, root) {
					entry, err := DecodeEntry(v)
					if err != nil {
						return err
					}
					entries[b.Name] = *entry
				} else {
					childBucketPath := b.Name + string(k)
					if v == nil {
						toVisit = append(toVisit, namedBucket{
							childBucketPath + "/",
							b.Bucket.Bucket(k),
						})
					} else {
						entry, err := DecodeEntry(v)
						if err != nil {
							return err
						}
						entries[childBucketPath] = *entry
					}
				}
			}
			return nil
		}

		for len(toVisit) > 0 {
			if err := visit(toVisit[0]); err != nil {
				return err
			}
			toVisit = toVisit[1:]
		}
		return nil
	})
	return
}

func (d *DB) Close() {
	d.db.Close()
}

func EncodeEntry(entry *Entry) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(entry); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func DecodeEntry(v []byte) (*Entry, error) {
	buf := bytes.NewBuffer(nil)
	dec := gob.NewDecoder(buf)
	buf.Write(v)
	var e Entry
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("meta: error decoding entry: %v", err)
	}
	return &e, nil
}

type namedBucket struct {
	Name   string
	Bucket *bolt.Bucket
}
