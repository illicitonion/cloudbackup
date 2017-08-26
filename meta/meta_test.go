package meta

import (
	"bytes"
	"encoding/gob"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"testing"

	"github.com/boltdb/bolt"
)

var (
	noFn = func(db *DB, t *testing.T) {}

	entry = Entry{
		Bytes: 10,
		Chunks: []Chunk{
			Chunk{
				IV:            bytes.Repeat([]byte{0x00}, 16),
				CiphertextMAC: bytes.Repeat([]byte{0xFF}, 32),
			},
		},
		Mode:  0700,
		User:  "foo",
		Group: "bar",
	}
	entryBytes = encode(&entry)

	otherEntry = Entry{
		Bytes: 20,
		Chunks: []Chunk{
			Chunk{
				IV:            bytes.Repeat([]byte{0xF0}, 16),
				CiphertextMAC: bytes.Repeat([]byte{0x0F}, 32),
			},
		},
		Mode:  0755,
		User:  "dr",
		Group: "who",
	}
	otherEntryBytes = encode(&otherEntry)
)

func TestPutInRoot(t *testing.T) {
	db, cleanup := makeDB(t)
	defer cleanup()

	newBuckets, err := db.Put("file", &entry)
	if err != nil {
		t.Fatal(err)
	}

	if len(newBuckets) > 0 {
		t.Errorf("want newBuckets empty, got %v", newBuckets)
	}

	db.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(root)
		if bucket == nil {
			t.Fatal("Root bucket was nil")
		}
		if got := bucket.Get([]byte("file")); !reflect.DeepEqual(entryBytes, got) {
			t.Errorf("./file want % X got % X", entryBytes, got)
		}
		return nil
	})
}

func TestPutInDirectory(t *testing.T) {
	testPut(t, noFn, noFn, []string{"dir", "dir/subdir"})
}

func TestPutPartialDirectoryExists(t *testing.T) {
	testPut(t, func(db *DB, t *testing.T) {
		db.db.Update(func(tx *bolt.Tx) error {
			bucket, err := tx.CreateBucket(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := bucket.CreateBucket([]byte("dir")); err != nil {
				t.Fatal(err)
			}
			return nil
		})
	}, noFn, []string{"dir/subdir"})
}

func TestPutInExistingDirectory(t *testing.T) {
	testPut(t, func(db *DB, t *testing.T) {
		db.db.Update(func(tx *bolt.Tx) error {
			bucket, err := tx.CreateBucket(root)
			if err != nil {
				t.Fatal(err)
			}
			if bucket, err = bucket.CreateBucket([]byte("dir")); err != nil {
				t.Fatal(err)
			}
			if bucket, err = bucket.CreateBucket([]byte("subdir")); err != nil {
				t.Fatal(err)
			}
			if err := bucket.Put([]byte("otherfile"), otherEntryBytes); err != nil {
				t.Fatal(err)
			}
			return nil
		})
	}, func(db *DB, t *testing.T) {
		db.db.View(func(tx *bolt.Tx) error {
			bucket := tx.Bucket(root).Bucket([]byte("dir")).Bucket([]byte("subdir"))
			if got := bucket.Get([]byte("otherfile")); !reflect.DeepEqual(otherEntryBytes, got) {
				t.Errorf("./file want % X got % X", otherEntryBytes, got)
			}
			return nil
		})
	}, []string{})
}

func TestPutEntryExists(t *testing.T) {
	testPut(t, func(db *DB, t *testing.T) {
		db.db.Update(func(tx *bolt.Tx) error {
			bucket, err := tx.CreateBucket(root)
			if err != nil {
				t.Fatal(err)
			}
			if bucket, err = bucket.CreateBucket([]byte("dir")); err != nil {
				t.Fatal(err)
			}
			if bucket, err = bucket.CreateBucket([]byte("subdir")); err != nil {
				t.Fatal(err)
			}
			if err := bucket.Put([]byte("file"), []byte("blah")); err != nil {
				t.Fatal(err)
			}
			return nil
		})
	}, noFn, []string{})
}

func makeDB(t *testing.T) (*DB, func()) {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	b, err := bolt.Open(f.Name(), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &DB{b}, func() { os.Remove(f.Name()) }
}

func testPut(t *testing.T, before func(*DB, *testing.T), after func(*DB, *testing.T), wantNewBuckets []string) {
	db, cleanup := makeDB(t)
	defer cleanup()

	before(db, t)

	gotNewBuckets, err := db.Put("dir/subdir/file", &entry)
	if err != nil {
		t.Fatal(err)
	}

	db.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(root)
		if bucket == nil {
			t.Fatal("Root bucket was nil")
		}
		bucket = bucket.Bucket([]byte("dir"))
		if bucket == nil {
			t.Fatal("dir bucket was nil")
		}
		bucket = bucket.Bucket([]byte("subdir"))
		if bucket == nil {
			t.Fatal("subdir bucket was nil")
		}
		if got := bucket.Get([]byte("file")); !reflect.DeepEqual(entryBytes, got) {
			t.Errorf("./file want % X got % X", entryBytes, got)
		}
		return nil
	})

	if !reflect.DeepEqual(wantNewBuckets, gotNewBuckets) {
		t.Errorf("want newBuckets %v, got %v", wantNewBuckets, gotNewBuckets)
	}

	after(db, t)
}

func TestGetInRoot(t *testing.T) {
	db, cleanup := makeDB(t)
	defer cleanup()

	db.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucket(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := bucket.Put([]byte("file"), entryBytes); err != nil {
			t.Fatal(err)
		}
		return nil
	})

	got, err := db.Get("file")
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]Entry{"file": entry}; !reflect.DeepEqual(got, want) {
		t.Errorf("file want % X got % X", want, got)
	}
}

func TestGetInDir(t *testing.T) {
	db, cleanup := makeDB(t)
	defer cleanup()

	if _, err := db.Put("dir/subdir/file", &entry); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Put("dir/subdir/otherfile", &otherEntry); err != nil {
		t.Fatal(err)
	}

	got, err := db.Get("dir/subdir/file")
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]Entry{"dir/subdir/file": entry}; !reflect.DeepEqual(got, want) {
		t.Errorf("dir/subdir/file want % X got % X", want, got)
	}
}

func TestGetDir(t *testing.T) {
	db, cleanup := makeDB(t)
	defer cleanup()

	if _, err := db.Put("dir/subdir/file", &entry); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Put("dir/subdir/otherfile", &otherEntry); err != nil {
		t.Fatal(err)
	}

	got, err := db.Get("dir/subdir")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Entry{
		"dir/subdir/file":      entry,
		"dir/subdir/otherfile": otherEntry,
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("dir/subdir want %v got %v", want, got)
	}
}

func TestGetDirWithSubdir(t *testing.T) {
	db, cleanup := makeDB(t)
	defer cleanup()

	if _, err := db.Put("dir/file", &entry); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Put("dir/subdir/otherfile", &otherEntry); err != nil {
		t.Fatal(err)
	}

	got, err := db.Get("dir")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Entry{
		"dir/file":             entry,
		"dir/subdir/otherfile": otherEntry,
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("dir want %v got %v", want, got)
	}
}

func TestGetRoot(t *testing.T) {
	db, cleanup := makeDB(t)
	defer cleanup()

	if _, err := db.Put("file", &entry); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Put("dir/file", &entry); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Put("dir/subdir/otherfile", &otherEntry); err != nil {
		t.Fatal(err)
	}

	got, err := db.Get(".")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Entry{
		"file":                 entry,
		"dir/file":             entry,
		"dir/subdir/otherfile": otherEntry,
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("dir want %v got %v", want, got)
	}
}

func encode(e *Entry) []byte {
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(entry); err != nil {
		log.Fatal("Could not encode entry: ", err)
	}
	return buf.Bytes()[:]
}
