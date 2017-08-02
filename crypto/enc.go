package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

func Encrypt(aesKey, hmacKey, iv, plaintext []byte, chunkSize int) (ciphertext, ciphertextMAC []byte, err error) {
	if chunkSize < len(plaintext) {
		return nil, nil, fmt.Errorf("chunkSize %v must be at least plaintext length %v", chunkSize, len(plaintext))
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, err
	}

	bm := cipher.NewCBCEncrypter(block, iv)

	paddedPlaintext := pad(plaintext, chunkSize)
	ciphertext = make([]byte, len(paddedPlaintext))

	bm.CryptBlocks(ciphertext, paddedPlaintext)

	ciphertextHasher := hmac.New(sha256.New, hmacKey)
	ciphertextHasher.Write(ciphertext)
	ciphertextMAC = ciphertextHasher.Sum(nil)

	return
}

// Pads unpadded with repeated 0x00s.
func pad(unpadded []byte, desiredLength int) []byte {
	if len(unpadded) == desiredLength {
		return unpadded
	}
	toAppend := desiredLength - len(unpadded)
	return append(unpadded, bytes.Repeat([]byte{byte(0x00)}, toAppend)...)
}
