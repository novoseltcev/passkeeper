package jwtmanager

import (
	"context"
	"time"
)

// Token is a JWT token representation.
//
// It is used to load/store token data in/from storage.
type Token struct {
	ID        string
	Subject   string
	ExpiresAt time.Time
}

//go:generate mockgen -source=storage.go -destination=mocks/storage.go -package=mocks -typed

// TokenStorager is a interface for token storage.
type TokenStorager interface {
	Load(ctx context.Context, id string) (*Token, error)
	Store(ctx context.Context, token Token) error
}
