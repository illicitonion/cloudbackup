package crypto

import (
	"bytes"
	"crypto/aes"
	"reflect"
	"testing"
)

func TestDecrypt(t *testing.T) {
	plaintext, err := Decrypt(allZeros, allOnes, iv, fooCiphertext, fooMAC)
	if err != nil {
		t.Errorf("err: want nil got %v", err)
	}
	if !reflect.DeepEqual(plaintext[:len(foo)], foo) {
		t.Errorf("plaintext: want % X got % X", foo, plaintext)
	}
}

func TestDecryptExactBlock(t *testing.T) {
	plaintext, err := Decrypt(allZeros, allOnes, iv, blockCiphertext, blockMAC)
	if err != nil {
		t.Errorf("err: want nil got %v", err)
	}
	if !reflect.DeepEqual(plaintext, block) {
		t.Errorf("plaintext: want % X got % X", block, plaintext)
	}
}

func TestDecryptPaddedBlock(t *testing.T) {
	plaintext, err := Decrypt(allZeros, allOnes, iv, blockPaddedCiphertext, blockPaddedMAC)
	if err != nil {
		t.Errorf("err: want nil got %v", err)
	}
	if !reflect.DeepEqual(plaintext[:len(block)], block) {
		t.Errorf("plaintext: want % X got % X", block, plaintext)
	}
}

func TestDecryptWrongHMAC(t *testing.T) {
	plaintext, err := Decrypt(allZeros, allOnes, iv, fooCiphertext, allZeros)
	if err == nil {
		t.Errorf("err: want non-nil got nil")
	}
	if plaintext != nil {
		t.Errorf("plaintext: want nil got % X", plaintext)
	}
}

func TestDecryptWrongIV(t *testing.T) {
	plaintext, err := Decrypt(allZeros, allOnes, bytes.Repeat([]byte{0xFF}, aes.BlockSize), fooCiphertext, fooMAC)
	if err != nil {
		t.Errorf("err: want nil got %v", err)
	}
	if reflect.DeepEqual(plaintext, foo) {
		t.Errorf("plaintext: want not % X got % X", foo, plaintext)
	}
}

func TestDecryptBadAESKeySize(t *testing.T) {
	_, err := Decrypt([]byte{0x00}, allOnes, iv, fooCiphertext, fooMAC)
	if err == nil {
		t.Errorf("err: want non-nil got nil")
	}
}

func TestDecryptBadHMACKeySize(t *testing.T) {
	_, err := Decrypt(allZeros, []byte{0x00}, iv, fooCiphertext, fooMAC)
	if err == nil {
		t.Errorf("err: want non-nil got nil")
	}
}
