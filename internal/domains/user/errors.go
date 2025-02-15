package user

import "errors"

var (
	ErrUserNotFound        = errors.New("user not found")
	ErrAutenticationFailed = errors.New("authentication failed")
	ErrLoginIsBusy         = errors.New("login is busy")
	ErrInvalidSecretKey    = errors.New("invalid secret key")
)
