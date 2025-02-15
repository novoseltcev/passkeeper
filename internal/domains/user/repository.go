package user

import (
	"context"

	"github.com/novoseltcev/passkeeper/internal/models"
)

//go:generate mockgen -destination=./mocks/repository_mock.go -package=mocks -source=repository.go -typed

type Repository interface {
	GetByLogin(ctx context.Context, login string) (*models.User, error)
	GetByID(ctx context.Context, id models.UserID) (*models.User, error)
	CreateAccount(ctx context.Context, data *models.User) (models.UserID, error)
}
