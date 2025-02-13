package secrets

import "errors"

var (
	ErrSecretNotFound    = errors.New("secret not found")
	ErrAnotherOwner      = errors.New("another owner")
	ErrInvalidSecretKey  = errors.New("invalid secret key")
	ErrInvalidSecretType = errors.New("invalid secret type")
)
