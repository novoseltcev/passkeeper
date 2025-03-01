package pwdhash

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type BCryptHasher struct {
	cost int
}

var _ Hasher = (*BCryptHasher)(nil)

func NewBCrypt(cost int) *BCryptHasher {
	return &BCryptHasher{
		cost: cost,
	}
}

// Generate hashes the given data using bcrypt.
func (h *BCryptHasher) Generate(data string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(data), h.cost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// Compare compares the given data with the hash.
func (h *BCryptHasher) Compare(hash, data string) (bool, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(data)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}
