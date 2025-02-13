// Package secrets provides a domain for secrets.
package secrets

import (
	"context"
	"crypto/hmac"

	"github.com/novoseltcev/passkeeper/internal/models"
)

//go:generate mockgen -destination=./mocks/service_mocks.go -package=mocks -source=service.go -typed
type Page[T any] struct {
	Items []T
	Pages uint64
}

func NewPage[T any](items []T, pages uint64) *Page[T] {
	return &Page[T]{Items: items, Pages: pages}
}

type ISecretData interface {
	ToString() string
	SecretType() models.SecretType
}

// Service is a domain service for secrets.
type Service interface {
	// Get returns a secret by its ID with checking the owner by ownerID.
	//
	// Its check owner by ownerID to grant private access.
	// Domain errors:
	// - ErrSecretNotFound
	// - ErrAnotherOwner
	Get(ctx context.Context, id models.SecretID, ownerID models.UserID) (*models.Secret, error)

	// GetPage returns a page of owner's secrets with pagination.
	// If the owner is not found, an error will be returned.
	GetPage(ctx context.Context, ownerID models.UserID, page, limit uint64) (*Page[models.Secret], error)

	// Delete deletes a secret by its ID.
	//
	// Its check owner by ownerID to grant private access.
	// Domain errors:
	// - ErrSecretNotFound
	// - ErrAnotherOwner
	Delete(ctx context.Context, id models.SecretID, ownerID models.UserID) error

	// CreateText creates a new text secret.
	//
	// Its validate secretKey and encrypt data.
	// Domain errors:
	// - ErrInvalidSecretKey
	Create(
		ctx context.Context,
		ownerID models.UserID,
		secretKey string,
		name string,
		data ISecretData,
	) (models.SecretID, error)

	// Update update a secret.
	//
	// Its validate secretKey and encrypt data.
	// Domain errors:
	// - ErrSecretNotFound
	// - ErrAnotherOwner
	// - ErrInvalidSecretKey
	// - ErrInvalidSecretType
	Update(
		ctx context.Context,
		id models.SecretID,
		ownerID models.UserID,
		secretKey string,
		name string,
		data ISecretData,
	) error
}

type Hasher interface {
	Hash(v string) ([]byte, error)
}

type Encryptor interface {
	Encrypt(v string) ([]byte, error)
}

type EncryptorFactory interface {
	Create(secretKey string) Encryptor
}

type service struct {
	repo             Repository
	hasher           Hasher
	encryptorFactory EncryptorFactory
}

var _ Service = (*service)(nil)

func NewService(
	repo Repository,
	hasher Hasher,
	encryptorFactory EncryptorFactory,
) *service { // nolint: revive
	return &service{repo: repo, hasher: hasher, encryptorFactory: encryptorFactory}
}

func (s *service) Get(ctx context.Context, id models.SecretID, ownerID models.UserID) (*models.Secret, error) {
	return s.getMySecret(ctx, id, ownerID)
}

func (s *service) GetPage(ctx context.Context,
	ownerID models.UserID, page, limit uint64,
) (*Page[models.Secret], error) {
	return s.repo.GetPage(ctx, ownerID, page, limit)
}

func (s *service) Create(
	ctx context.Context, ownerID models.UserID, secretKey string, name string, data ISecretData,
) (models.SecretID, error) {
	owner, err := s.loadAndCheckOwner(ctx, ownerID, secretKey)
	if err != nil {
		return "", err
	}

	encryptedData, err := s.encryptorFactory.Create(secretKey).Encrypt(data.ToString())
	if err != nil {
		return "", err
	}

	return s.repo.Create(ctx, models.NewSecret(name, data.SecretType(), encryptedData, owner))
}

func (s *service) Update(
	ctx context.Context,
	id models.SecretID, ownerID models.UserID,
	secretKey string,
	name string, data ISecretData,
) error {
	secret, err := s.getMySecret(ctx, id, ownerID)
	if err != nil {
		return err
	}

	if data.SecretType() != secret.Type {
		return ErrInvalidSecretType
	}

	if err := s.checkSecretKey(secret.Owner, secretKey); err != nil {
		return err
	}

	encData, err := s.encryptorFactory.Create(secretKey).Encrypt(data.ToString())
	if err != nil {
		return err
	}

	secret.Data = encData
	secret.Name = name

	return s.repo.Update(ctx, id, secret)
}

func (s *service) Delete(ctx context.Context, id models.SecretID, ownerID models.UserID) error {
	_, err := s.getMySecret(ctx, id, ownerID)
	if err != nil {
		return err
	}

	return s.repo.Delete(ctx, id)
}

func (s *service) getMySecret(
	ctx context.Context,
	id models.SecretID,
	ownerID models.UserID,
) (*models.Secret, error) {
	secret, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	if secret.Owner.ID != ownerID {
		return nil, ErrAnotherOwner
	}

	return secret, nil
}

func (s *service) checkSecretKey(owner *models.User, secretKey string) error {
	hashedSecretKey, err := s.hasher.Hash(secretKey)
	if err != nil {
		return err
	}

	if !hmac.Equal(owner.SecretKeyHash, hashedSecretKey) {
		return ErrInvalidSecretKey
	}

	return nil
}

func (s *service) loadAndCheckOwner(
	ctx context.Context,
	ownerID models.UserID,
	secretKey string,
) (*models.User, error) {
	owner, err := s.repo.GetOwner(ctx, ownerID)
	if err != nil {
		return nil, err
	}

	if err := s.checkSecretKey(owner, secretKey); err != nil {
		return nil, err
	}

	return owner, nil
}
