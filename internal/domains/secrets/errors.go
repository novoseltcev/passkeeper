package secrets

import "errors"

var (
	ErrSecretNotFound    = errors.New("secret not found")
	ErrAnotherOwner      = errors.New("another owner")
	ErrInvalidPassphrase = errors.New("invalid passphrase")
	ErrInvalidSecretType = errors.New("invalid secret type")
)
