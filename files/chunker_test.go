package files

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

var abc = []byte("abc")

func TestReadLessThanOneChunk(t *testing.T) {
	next := readChunks(t, 10)
	read, hasNext, err := next()
	if err != nil {
		t.Errorf("err: want nil, got %v", err)
	}
	if !reflect.DeepEqual(read, abc) {
		t.Errorf("read: want % X got % X", abc, read)
	}
	if hasNext {
		t.Errorf("hasNext: want false got true")
	}

	read2, hasNext2, err2 := next()
	if err2 != nil {
		t.Errorf("err2: want nil, got %v", err2)
	}
	if read2 != nil {
		t.Errorf("read2: want % X got % X", nil, read2)
	}
	if hasNext2 {
		t.Errorf("hasNext2: want false got true")
	}
}

func TestReadOneChunk(t *testing.T) {
	next := readChunks(t, 3)
	read, hasNext, err := next()
	if err != nil {
		t.Errorf("err: want nil, got %v", err)
	}
	if !reflect.DeepEqual(read, abc) {
		t.Errorf("read: want % X got % X", abc, read)
	}
	if hasNext {
		t.Errorf("hasNext: want false got true")
	}

	read2, hasNext2, err2 := next()
	if err2 != nil {
		t.Errorf("err2: want nil, got %v", err2)
	}
	if read2 != nil {
		t.Errorf("read2: want % X got % X", nil, read2)
	}
	if hasNext2 {
		t.Errorf("hasNext2: want false got true")
	}
}

func TestReadTwoChunks(t *testing.T) {
	next := readChunks(t, 2)
	read, hasNext, err := next()
	if err != nil {
		t.Errorf("err: want nil, got %v", err)
	}
	if want := abc[:2]; !reflect.DeepEqual(read, want) {
		t.Errorf("read: want % X got % X", want, read)
	}
	if !hasNext {
		t.Errorf("hasNext: want true got false")
	}

	read2, hasNext2, err2 := next()
	if err2 != nil {
		t.Errorf("err2: want nil, got %v", err2)
	}
	if want := abc[2:]; !reflect.DeepEqual(read2, want) {
		t.Errorf("read2: want % X got % X", want, read2)
	}
	if hasNext2 {
		t.Errorf("hasNext2: want false got true")
	}

	read3, hasNext3, err3 := next()
	if err3 != nil {
		t.Errorf("err3: want nil, got %v", err3)
	}
	if read3 != nil {
		t.Errorf("read3: want % X got % X", nil, read3)
	}
	if hasNext3 {
		t.Errorf("hasNext3: want false got true")
	}
}

func TestReadThreeChunks(t *testing.T) {
	next := readChunks(t, 1)
	read, hasNext, err := next()
	if err != nil {
		t.Errorf("err: want nil, got %v", err)
	}
	if want := abc[:1]; !reflect.DeepEqual(read, want) {
		t.Errorf("read: want % X got % X", want, read)
	}
	if !hasNext {
		t.Errorf("hasNext: want true got false")
	}

	read2, hasNext2, err2 := next()
	if err2 != nil {
		t.Errorf("err2: want nil, got %v", err2)
	}
	if want := abc[1:2]; !reflect.DeepEqual(read2, want) {
		t.Errorf("read2: want % X got % X", want, read2)
	}
	if !hasNext2 {
		t.Errorf("hasNext2: want true got false")
	}

	read3, hasNext3, err3 := next()
	if err3 != nil {
		t.Errorf("err3: want nil, got %v", err3)
	}
	if want := abc[2:3]; !reflect.DeepEqual(read3, want) {
		t.Errorf("read3: want % X got % X", want, read3)
	}
	if hasNext3 {
		t.Errorf("hasNext3: want false got true")
	}

	read4, hasNext4, err4 := next()
	if err4 != nil {
		t.Errorf("err4: want nil, got %v", err4)
	}
	if read4 != nil {
		t.Errorf("read4: want % X got % X", nil, read4)
	}
	if hasNext4 {
		t.Errorf("hasNext4: want false got true")
	}
}

func readChunks(t *testing.T, chunkBytes int) func() (read []byte, hasNext bool, err error) {
	return ReadChunks("", writeFile(t), chunkBytes, int64(len(abc)))
}

func writeFile(t *testing.T) *os.File {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(abc); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	return f
}
