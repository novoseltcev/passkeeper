package jwtmanager

import (
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

var (
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")
	ErrTokenInvalidSubject     = errors.New("token has invalid id")
	ErrTokenWithoutExpiration  = errors.New("token has no expiration")
	ErrTokenNotFound           = errors.New("token not found in storage")
)

const (
	ValidationErrorSubject uint32 = (jwt.ValidationErrorClaimsInvalid * 2) << iota // nolint: mnd
	ValidationErrorWithoutExpiration
)

// ParseError is a JWT parsing error.
//
// Wraps jwt.ValidationError.
type ParseError struct {
	jwt.ValidationError
}

func (e ParseError) Is(err error) bool {
	if b := e.ValidationError.Is(err); b {
		return true
	}

	switch err {
	case ErrTokenInvalidSubject:
		return e.Errors&ValidationErrorSubject != 0
	case ErrTokenWithoutExpiration:
		return e.Errors&ValidationErrorWithoutExpiration != 0
	}

	return false
}
