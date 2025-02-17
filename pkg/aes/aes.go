package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

var ErrInvalidDataLen = errors.New("invalid data length")

const (
	AES_128_BIT_KEY_LENGTH = 16
	AES_192_BIT_KEY_LENGTH = 24
	AES_256_BIT_KEY_LENGTH = 32
)

type AES struct {
	keyLength int
}

func New(keyLength int) *AES {
	return &AES{
		keyLength: keyLength,
	}
}

// Encrypt encrypts data with AES-GCM.
//
// The nonce is randomly generated and prepended to the encrypted data.
func (a *AES) Encrypt(key, data []byte) ([]byte, error) {
	if len(key) < a.keyLength {
		var err error
		if key, err = a.expandKey(key); err != nil {
			return nil, err
		}
	}

	c, err := aes.NewCipher(key[:a.keyLength])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypt decrypts data with AES-GCM.
//
// The nonce is expected to be prepended to the encrypted data.
func (a *AES) Decrypt(key, data []byte) ([]byte, error) {
	if len(key) < a.keyLength {
		var err error
		if key, err = a.expandKey(key); err != nil {
			return nil, err
		}
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrInvalidDataLen
	}

	return gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
}

func (a *AES) expandKey(key []byte) ([]byte, error) {
	hash := sha256.New()
	if _, err := hash.Write(key); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}
