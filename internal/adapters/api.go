package adapters

import (
	"context"
	"errors"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/secrets"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/user"
)

var ErrUnauthorized = errors.New("unauthorized")

type API interface {
	GetSecretsPage(
		ctx context.Context,
		token string,
		params *secrets.PaginationRequest,
	) ([]secrets.SecretItemSchema, uint64, error)

	DecryptSecret(
		ctx context.Context,
		token string,
		uuid string,
		data *secrets.DecryptByIDData,
	) (*secrets.SecretSchema, error)

	Add(ctx context.Context, token string, data any) (string, error)
	Update(ctx context.Context, token string, uuid string, data any) error
	DeleteSecret(ctx context.Context, token string, uuid string) error

	Login(ctx context.Context, data *user.LoginData) (string, error)
	Register(ctx context.Context, data *user.RegisterData) (string, error)
	Verify(ctx context.Context, token string, data *user.VerifyData) error
}
