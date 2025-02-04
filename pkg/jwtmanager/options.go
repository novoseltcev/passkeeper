package jwtmanager

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Option func(m *manager)

// WithExpiration sets expiration time (exp claim) for token.
func WithExpiration(exp time.Duration) Option {
	return func(m *manager) {
		m.exp = exp
	}
}

// WithIssuer sets issuer (iss claim) for token.
func WithIssuer(issuer string) Option {
	return func(m *manager) {
		m.issuer = issuer
	}
}

// WithAlgorithm sets signing algorithm for token.
func WithAlgorithm(alg jwt.SigningMethod) Option {
	return func(m *manager) {
		m.alg = alg
	}
}

// WithTokenStorage sets token storage.
func WithTokenStorage(storage TokenStorager) Option {
	return func(m *manager) {
		m.storage = storage
	}
}
