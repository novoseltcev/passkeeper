package secrets

import (
	"context"

	"github.com/novoseltcev/passkeeper/internal/models"
)

//go:generate mockgen -destination=mocks/repository_mock.go -package=mocks -source=repository.go -typed

type Repository interface {
	GetOwner(ctx context.Context, ownerID models.UserID) (*models.User, error)
	Get(ctx context.Context, id models.SecretID) (*models.Secret, error)
	GetPage(ctx context.Context, ownerID models.UserID, limit, offset uint64) (*Page[models.Secret], error)
	Create(ctx context.Context, data *models.Secret) (models.SecretID, error)
	Update(ctx context.Context, id models.SecretID, data *models.Secret) error
	Delete(ctx context.Context, id models.SecretID) error
}
