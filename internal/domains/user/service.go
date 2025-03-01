// Package user provides a domain for users.
package user

import (
	"context"
	"errors"

	"github.com/novoseltcev/passkeeper/internal/models"
)

//go:generate mockgen -destination=./mocks/service_mocks.go -package=mocks -source=service.go -typed

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
	Register(ctx context.Context, login, password, passphrase string) (models.UserID, error)

	// VerifyPassphrase verifies a owner's passphrase.
	//
	// Errors:
	// - ErrInvalidSecretType
	VerifyPassphrase(ctx context.Context, ownerID models.UserID, passphrase string) error
}

type Hasher interface {
	Generate(v string) (string, error)
	Compare(hash, v string) (bool, error)
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
			return "", ErrAuthenticationFailed
		}

		return "", err
	}

	ok, err := s.hasher.Compare(user.PasswordHash, password)
	if err != nil {
		return "", err
	}

	if !ok {
		return "", ErrAuthenticationFailed
	}

	return user.ID, nil
}

func (s *service) Register(ctx context.Context, login, password, passphrase string) (models.UserID, error) {
	user, err := s.repo.GetByLogin(ctx, login)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return "", err
	}

	if user != nil {
		return "", ErrLoginIsBusy
	}

	hashedPwd, err := s.hasher.Generate(password)
	if err != nil {
		return "", err
	}

	hashedPassphrase, err := s.hasher.Generate(passphrase)
	if err != nil {
		return "", err
	}

	return s.repo.CreateAccount(ctx, models.NewUser(login, hashedPwd, hashedPassphrase))
}

func (s *service) VerifyPassphrase(ctx context.Context, ownerID models.UserID, passphrase string) error {
	owner, err := s.repo.GetByID(ctx, ownerID)
	if err != nil {
		return err
	}

	ok, err := s.hasher.Compare(owner.PassphraseHash, passphrase)
	if err != nil {
		return err
	}

	if !ok {
		return ErrInvalidPassphrase
	}

	return nil
}
