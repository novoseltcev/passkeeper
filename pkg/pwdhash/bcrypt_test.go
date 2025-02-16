package pwdhash_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/novoseltcev/passkeeper/pkg/pwdhash"
)

func TestBCrypt_Generate_Fails(t *testing.T) {
	t.Parallel()
	hasher := pwdhash.NewBCrypt(12)

	_, err := hasher.Generate(strings.Repeat("a", 73))
	assert.ErrorIs(t, err, bcrypt.ErrPasswordTooLong)
}

func TestBCrypt_Compare(t *testing.T) {
	t.Parallel()
	hasher := pwdhash.NewBCrypt(12)

	hash, err := hasher.Generate("test")
	require.NoError(t, err)

	ok, err := hasher.Compare(hash, "test")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestBCrypt_Compare_Fails(t *testing.T) {
	t.Parallel()
	hasher := pwdhash.NewBCrypt(12)

	hash, err := hasher.Generate("test")
	require.NoError(t, err)

	ok, err := hasher.Compare(hash, "wrong")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestBCrypt_Compare_Fails_Error(t *testing.T) {
	t.Parallel()

	ok, err := pwdhash.NewBCrypt(12).Compare("", "wrong")
	require.ErrorIs(t, err, bcrypt.ErrHashTooShort)
	assert.False(t, ok)
}
