// Package jwtmanager provides JWT manager.
//
// JWT manager is a tool for generating and parsing JWT tokens.
// It also provides feature to store tokens in storage.
package jwtmanager

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

const (
	defaultExpiration = time.Hour * 24 * 7 // 7 days
)

// JWTManager is a JWT manager, which can generate and parse JWT tokens.
type JWTManager struct {
	issuer  string
	exp     time.Duration
	alg     jwt.SigningMethod
	key     string
	storage TokenStorager
}

// New creates new JWTManager.
func New(key string, opts ...Option) *JWTManager {
	mngr := &JWTManager{
		exp: defaultExpiration,
		alg: jwt.SigningMethodHS256,
		key: key,
	}

	for _, opt := range opts {
		opt(mngr)
	}

	return mngr
}

// GenerateToken generates new token.
//
// If token not valid or not found in storage, it returns ParseError.
func (j *JWTManager) GenerateToken(subject string) (string, error) {
	now := time.Now()
	expAt := now.Add(j.exp)

	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expAt),
		Issuer:    j.issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		Subject:   subject,
	}

	if err := claims.Valid(); err != nil {
		return "", err
	}

	if j.storage != nil {
		uid, err := uuid.NewRandom()
		if err != nil {
			return "", err
		}

		claims.ID = uid.String()
		if err := j.storage.Store(Token{
			ID:        claims.ID,
			Subject:   subject,
			ExpiresAt: expAt,
		}); err != nil {
			return "", fmt.Errorf("failed to add token to storage: %w", err)
		}
	}

	return jwt.NewWithClaims(j.alg, claims).SignedString([]byte(j.key))
}

func (j *JWTManager) parse(tokenString string) (*Token, error) {
	var claims jwt.RegisteredClaims
	if _, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		func(_ *jwt.Token) (interface{}, error) { return []byte(j.key), nil },
		jwt.WithValidMethods([]string{j.alg.Alg()}),
	); err != nil {
		return nil, err
	}

	if claims.Subject == "" {
		return nil, ParseError{*jwt.NewValidationError("token should have subject", ValidationErrorSubject)}
	}

	if claims.ExpiresAt == nil {
		return nil, ParseError{*jwt.NewValidationError("forbidden unexpired tokens", ValidationErrorWithoutExpiration)}
	}

	if j.issuer != "" && claims.Issuer != j.issuer {
		return nil, ParseError{
			*jwt.NewValidationError("token has invalid issuer "+claims.Issuer, jwt.ValidationErrorIssuer),
		}
	}

	if j.storage != nil {
		if claims.ID == "" {
			return nil, ParseError{*jwt.NewValidationError("token should have id", jwt.ValidationErrorId)}
		}

		if _, err := uuid.Parse(claims.ID); err != nil {
			return nil, ParseError{*jwt.NewValidationError("token id is not valid uuid", jwt.ValidationErrorId)}
		}
	}

	return &Token{
		ID:        claims.ID,
		Subject:   claims.Subject,
		ExpiresAt: claims.ExpiresAt.Time,
	}, nil
}

// ParseToken parses token string and returns token.
//
// If token not valid or not found in storage, it returns ParseError.
func (j *JWTManager) ParseToken(tokenString string) (*Token, error) {
	token, err := j.parse(tokenString)
	if err != nil {
		return nil, err
	}

	if j.storage != nil {
		_, err := j.storage.Load(token.ID)
		if err != nil {
			if errors.Is(err, ErrTokenNotFound) {
				return nil, ParseError{ValidationError: jwt.ValidationError{
					Inner:  ErrTokenNotFound,
					Errors: jwt.ValidationErrorExpired,
				}}
			}

			return nil, err
		}
	}

	return token, nil
}
