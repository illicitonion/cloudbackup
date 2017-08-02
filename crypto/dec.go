package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

func Decrypt(aesKey, hmacKey, iv, ciphertext, expectedCiphertextMAC []byte) (plaintext []byte, err error) {
	if err := verifyMAC(hmacKey, ciphertext, expectedCiphertextMAC); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	bm := cipher.NewCBCDecrypter(block, iv)
	paddedPlaintext := make([]byte, len(ciphertext))
	bm.CryptBlocks(paddedPlaintext, ciphertext)
	return paddedPlaintext, nil
}

func verifyMAC(key, body, wantMAC []byte) error {
	hasher := hmac.New(sha256.New, key)
	hasher.Write(body)
	gotMAC := hasher.Sum(nil)
	if !hmac.Equal(wantMAC, gotMAC) {
		return fmt.Errorf("wrong HMAC")
	}
	return nil
}
