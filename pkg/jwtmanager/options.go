package jwtmanager

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Option func(j *JWTManager)

// WithExpiration sets expiration time (exp claim) for token.
func WithExpiration(exp time.Duration) Option {
	return func(j *JWTManager) {
		j.exp = exp
	}
}

// WithIssuer sets issuer (iss claim) for token.
func WithIssuer(issuer string) Option {
	return func(j *JWTManager) {
		j.issuer = issuer
	}
}

// WithAlgorithm sets signing algorithm for token.
func WithAlgorithm(alg jwt.SigningMethod) Option {
	return func(j *JWTManager) {
		j.alg = alg
	}
}

// WithTokenStorage sets token storage.
func WithTokenStorage(storage TokenStorager) Option {
	return func(j *JWTManager) {
		j.storage = storage
	}
}
