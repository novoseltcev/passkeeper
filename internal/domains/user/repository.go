package user

import (
	"context"

	"github.com/novoseltcev/passkeeper/internal/models"
)

type Repository interface {
	GetByLogin(ctx context.Context, login string) (*models.User, error)
	GetByID(ctx context.Context, id models.UserID) (*models.User, error)
	CreateAccount(ctx context.Context, data *models.User) (models.UserID, error)
}
