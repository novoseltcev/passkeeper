package user

import "errors"

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrLoginIsBusy          = errors.New("login is busy")
	ErrInvalidPassphrase    = errors.New("invalid passphrase")
)
