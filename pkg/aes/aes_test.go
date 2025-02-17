package aes_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	aes "github.com/novoseltcev/passkeeper/pkg/aes"
)

func TestAES_Encrypt_and_Decrypt(t *testing.T) {
	t.Parallel()

	key := []byte(strings.Repeat("a", 16))
	data := []byte("data")

	gcm := aes.New(aes.AES_256_BIT_KEY_LENGTH)
	encrypted, err := gcm.Encrypt(key, data)
	require.NoError(t, err)

	decrypted, err := gcm.Decrypt(key, encrypted)
	require.NoError(t, err)

	assert.Equal(t, data, decrypted)
}

func TestAES_Encrypt_Fails_InvalidKeyLength(t *testing.T) {
	t.Parallel()

	_, err := aes.New(1).Encrypt([]byte("invalid-key"), nil)
	assert.ErrorContains(t, err, "crypto/aes: invalid key size")
}

func TestAES_Dencrypt_Fails_InvalidKeyLength(t *testing.T) {
	t.Parallel()

	_, err := aes.New(1).Decrypt([]byte("invalid-key"), nil)
	assert.ErrorContains(t, err, "crypto/aes: invalid key size")
}

func TestAES_Decrypt_Fails_InvalidDataLen(t *testing.T) {
	t.Parallel()

	_, err := aes.New(aes.AES_256_BIT_KEY_LENGTH).Decrypt([]byte("invalid-key"), nil)
	assert.ErrorContains(t, err, "invalid data length")
}
