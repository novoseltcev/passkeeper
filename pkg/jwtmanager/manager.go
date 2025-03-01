// Package jwtmanager provides JWT manager.
//
// JWT manager is a tool for generating and parsing JWT tokens.
// It also provides feature to store tokens in storage.
package jwtmanager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

const (
	defaultExpiration = time.Hour * 24 * 7 // 7 days
)

//go:generate mockgen -source=manager.go -destination=mocks/manager.go -package=mocks -typed

type Manager interface {
	GenerateToken(ctx context.Context, subject string) (string, error)
	ParseToken(ctx context.Context, tokenString string) (*Token, error)
}

// Manager is a JWT manager, which can generate and parse JWT tokens.
type manager struct {
	issuer  string
	exp     time.Duration
	alg     jwt.SigningMethod
	key     string
	storage TokenStorager
}

// New creates new JWT Manager.
func New(key string, opts ...Option) Manager {
	mngr := &manager{
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
func (mngr *manager) GenerateToken(ctx context.Context, subject string) (string, error) {
	now := time.Now()
	expAt := now.Add(mngr.exp)

	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expAt),
		Issuer:    mngr.issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		Subject:   subject,
	}

	if err := claims.Valid(); err != nil {
		return "", err
	}

	if mngr.storage != nil {
		uid, err := uuid.NewRandom()
		if err != nil {
			return "", err
		}

		claims.ID = uid.String()
		if err := mngr.storage.Store(ctx, Token{
			ID:        claims.ID,
			Subject:   subject,
			ExpiresAt: expAt,
		}); err != nil {
			return "", fmt.Errorf("failed to add token to storage: %w", err)
		}
	}

	return jwt.NewWithClaims(mngr.alg, claims).SignedString([]byte(mngr.key))
}

func (mngr *manager) parse(tokenString string) (*Token, error) {
	var claims jwt.RegisteredClaims
	if _, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		func(_ *jwt.Token) (interface{}, error) { return []byte(mngr.key), nil },
		jwt.WithValidMethods([]string{mngr.alg.Alg()}),
	); err != nil {
		return nil, err
	}

	if claims.Subject == "" {
		return nil, NewParseError("token should have subject", ValidationErrorSubject)
	}

	if claims.ExpiresAt == nil {
		return nil, NewParseError("forbidden unexpired tokens", ValidationErrorWithoutExpiration)
	}

	if mngr.issuer != "" && claims.Issuer != mngr.issuer {
		return nil, NewParseError("token has invalid issuer "+claims.Issuer, jwt.ValidationErrorIssuer)
	}

	if mngr.storage != nil {
		if claims.ID == "" {
			return nil, NewParseError("token should have id", jwt.ValidationErrorId)
		}

		if _, err := uuid.Parse(claims.ID); err != nil {
			return nil, NewParseError("token id is not valid uuid", jwt.ValidationErrorId)
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
func (mngr *manager) ParseToken(ctx context.Context, tokenString string) (*Token, error) {
	token, err := mngr.parse(tokenString)
	if err != nil {
		return nil, err
	}

	if mngr.storage != nil {
		_, err := mngr.storage.Load(ctx, token.ID)
		if err != nil {
			if errors.Is(err, ErrTokenNotFound) {
				return nil, &ParseError{ValidationError: jwt.ValidationError{
					Inner:  ErrTokenNotFound,
					Errors: jwt.ValidationErrorExpired,
				}}
			}

			return nil, err
		}
	}

	return token, nil
}
