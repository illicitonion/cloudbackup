package crypto

import (
	"bytes"
	"crypto/aes"
	"reflect"
	"testing"
)

var (
	allZeros = bytes.Repeat([]byte{0x00}, 32)

	allOnes = bytes.Repeat([]byte{0xFF}, 32)

	iv = bytes.Repeat([]byte{0x00}, aes.BlockSize)

	foo = []byte{'f', 'o', 'o'}

	fooCiphertext = []byte{
		0x2C, 0x7C, 0xD1, 0x94, 0x82, 0x25, 0x56, 0x6F,
		0xB5, 0x65, 0x4E, 0x54, 0x59, 0xB7, 0x46, 0x74,
	}

	fooMAC = []byte{
		0x95, 0x91, 0x31, 0xF4, 0x6B, 0x50, 0x53, 0xA2,
		0x03, 0xB7, 0xD0, 0x6B, 0x42, 0x8A, 0x86, 0x1E,
		0x51, 0xD1, 0x9C, 0x90, 0x88, 0x84, 0x17, 0xBB,
		0xF1, 0xD3, 0x57, 0x35, 0x8E, 0x42, 0x90, 0xF8,
	}

	block = []byte{
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', '0', '1', '2', '3', '4', '5',
	}

	blockCiphertext = []byte{
		0x61, 0xA6, 0x4C, 0xAA, 0x23, 0x5B, 0x6D, 0x6B,
		0xD4, 0xC7, 0x5B, 0xFF, 0x09, 0x15, 0x0B, 0x34,
	}

	blockMAC = []byte{
		0x4A, 0x3B, 0xB8, 0x32, 0xCB, 0x80, 0x95, 0x0B,
		0xC4, 0xDB, 0x05, 0x45, 0x5F, 0x3B, 0x54, 0x39,
		0x95, 0x67, 0x6C, 0x8B, 0xC6, 0x94, 0xB6, 0x88,
		0x63, 0x5F, 0xBF, 0xCB, 0x4D, 0x3F, 0x53, 0xCA,
	}

	blockPaddedCiphertext = []byte{
		0x61, 0xA6, 0x4C, 0xAA, 0x23, 0x5B, 0x6D, 0x6B,
		0xD4, 0xC7, 0x5B, 0xFF, 0x09, 0x15, 0x0B, 0x34,
		0xBE, 0xF2, 0xAB, 0x7F, 0xA4, 0x7F, 0xE7, 0x7B,
		0x95, 0x6F, 0xC8, 0xAD, 0x59, 0xAB, 0xBB, 0xCC,
	}

	blockPaddedMAC = []byte{
		0xF6, 0x4E, 0xC2, 0xF9, 0xE3, 0x42, 0x32, 0x6C,
		0xA6, 0x86, 0x45, 0x8C, 0x65, 0xF4, 0x88, 0x31,
		0xB1, 0x86, 0x7B, 0xBE, 0x91, 0x56, 0x3D, 0x18,
		0x7B, 0x1B, 0xE0, 0xED, 0x05, 0x08, 0xB3, 0x56,
	}
)

func TestEncrypt(t *testing.T) {
	gotCiphertext, gotMAC, gotErr := Encrypt(allZeros, allOnes, iv, foo, 16)
	if gotErr != nil {
		t.Errorf("err: want nil got %v", gotErr)
	}
	if !reflect.DeepEqual(gotCiphertext, fooCiphertext) {
		t.Errorf("ciphertext: want % X got % X", fooCiphertext, gotCiphertext)
	}
	if !reflect.DeepEqual(gotMAC, fooMAC) {
		t.Errorf("MAC: want % X got % X", fooMAC, gotMAC)
	}
}

func TestEncryptExactBlock(t *testing.T) {
	gotCiphertext, gotMAC, gotErr := Encrypt(allZeros, allOnes, iv, block, 16)
	if gotErr != nil {
		t.Errorf("err: want nil got %v", gotErr)
	}
	if !reflect.DeepEqual(gotCiphertext, blockCiphertext) {
		t.Errorf("ciphertext: want % X got % X", blockCiphertext, gotCiphertext)
	}
	if !reflect.DeepEqual(gotMAC, blockMAC) {
		t.Errorf("MAC: want % X got % X", blockMAC, gotMAC)
	}
}

func TestEncryptExactBlockWithPadding(t *testing.T) {
	gotCiphertext, gotMAC, gotErr := Encrypt(allZeros, allOnes, iv, block, 32)
	if gotErr != nil {
		t.Errorf("err: want nil got %v", gotErr)
	}
	if !reflect.DeepEqual(gotCiphertext, blockPaddedCiphertext) {
		t.Errorf("ciphertext: want % X got % X", blockPaddedCiphertext, gotCiphertext)
	}
	if !reflect.DeepEqual(gotMAC, blockPaddedMAC) {
		t.Errorf("MAC: want % X got % X", blockPaddedMAC, gotMAC)
	}
}

func TestEncryptBadAESKeySize(t *testing.T) {
	_, _, err := Encrypt([]byte{0x00}, allOnes, iv, []byte("foo"), 16)
	if err == nil {
		t.Errorf("err: want non-nil got nil")
	}
}

func TestPad(t *testing.T) {
	unpadded := []byte("foo")
	padded := pad(unpadded, 8)
	if !reflect.DeepEqual(unpadded, foo) {
		t.Errorf("unpadded: want % X got % X", foo, unpadded)
	}
	wantPadded := []byte{
		'f', 'o', 'o', 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	if !reflect.DeepEqual(padded, wantPadded) {
		t.Errorf("padded: want % X got % X", wantPadded, padded)
	}
}

func TestPadExactBlock(t *testing.T) {
	unpadded := []byte("foo")
	padded := pad(unpadded, 3)
	if !reflect.DeepEqual(unpadded, foo) {
		t.Errorf("unpadded: want % X got % X", foo, unpadded)
	}
	if !reflect.DeepEqual(padded, foo) {
		t.Errorf("padded: want % X got % X", foo, padded)
	}
}
