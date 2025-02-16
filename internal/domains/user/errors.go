package user

import "errors"

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrLoginIsBusy          = errors.New("login is busy")
	ErrInvalidSecretKey     = errors.New("invalid secret key")
)
