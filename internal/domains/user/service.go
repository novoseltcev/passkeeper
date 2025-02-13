// Package user provides a domain for users.
package user

import (
	"context"
	"crypto/hmac"
	"errors"

	"github.com/novoseltcev/passkeeper/internal/models"
)

// Service is a domain service for users.
type Service interface {
	// Login authenticates a user by login and password.
	//
	// Errors:
	// - ErrAutenticationFailed if the login or password is invalid.
	Login(ctx context.Context, login, password string) (models.UserID, error)

	// Register creates a new user.
	//
	// Errors:
	// - ErrLoginIsBusy if the login is busy.
	Register(ctx context.Context, login, password, secretKey string) (models.UserID, error)
}

type Hasher interface {
	Hash(v string) ([]byte, error)
}

type service struct {
	repo   Repository
	hasher Hasher
}

var _ Service = (*service)(nil)

func NewService(repo Repository, hasher Hasher) *service { // nolint: revive
	return &service{repo: repo, hasher: hasher}
}

func (s *service) Login(ctx context.Context, login, password string) (models.UserID, error) {
	user, err := s.repo.GetByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return "", ErrAutenticationFailed
		}

		return "", err
	}

	hashedPwd, err := s.hasher.Hash(password)
	if err != nil {
		return "", err
	}

	if !hmac.Equal(user.PasswordHash, hashedPwd) {
		return "", ErrAutenticationFailed
	}

	return user.ID, nil
}

func (s *service) Register(ctx context.Context, login, password, secretKey string) (models.UserID, error) {
	user, err := s.repo.GetByLogin(ctx, login)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return "", err
	}

	if user != nil {
		return "", ErrLoginIsBusy
	}

	hashedPwd, err := s.hasher.Hash(password)
	if err != nil {
		return "", err
	}

	hashedSecretKey, err := s.hasher.Hash(secretKey)
	if err != nil {
		return "", err
	}

	return s.repo.CreateAccount(ctx, models.NewUser(login, hashedPwd, hashedSecretKey))
}
