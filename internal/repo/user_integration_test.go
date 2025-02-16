package repo_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domain "github.com/novoseltcev/passkeeper/internal/domains/user"
	"github.com/novoseltcev/passkeeper/internal/models"
	"github.com/novoseltcev/passkeeper/internal/repo"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
	"github.com/novoseltcev/passkeeper/pkg/testutils/helpers"
)

var (
	migrationsDir = filepath.Join("..", "..", "migrations")
	ctxTimeout    = 10 * time.Second // nolint:mnd
)

const (
	accountUUID  = "62822284-5a2a-4a5d-b66e-12d09e0fe79c"
	sessionUUID1 = "b3055e06-9300-4d6a-9df1-b95e6fefc916"
	sessionUUID2 = "e065b8b6-6d1e-4d1b-bf58-52b0df58f147"
)

func TestUserRepository_GetByID(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	t.Cleanup(cancel)
	repo := repo.NewUserRepository(helpers.SetupDB(ctx, t, migrationsDir, "base.sql"))

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		user, err := repo.GetByID(ctx, models.UserID(accountUUID))
		require.NoError(t, err)
		assert.Equal(t, &models.User{
			ID:            models.UserID(accountUUID),
			Login:         "test@example.com",
			PasswordHash:  []byte{0x12, 0x34},
			SecretKeyHash: []byte{0x45, 0x67},
		}, user)
	})

	t.Run("Fails_NotFound", func(t *testing.T) {
		t.Parallel()

		_, err := repo.GetByID(ctx, models.UserID(uuid.NewString()))
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
	})

	t.Run("Fails_UUIDSyntaxError", func(t *testing.T) {
		t.Parallel()
		_, err := repo.GetByID(ctx, models.UserID(testutils.STRING))
		require.Error(t, err)

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "22P02", pgErr.Code)
	})
}

func TestUserRepository_GetByLogin(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	t.Cleanup(cancel)
	repo := repo.NewUserRepository(helpers.SetupDB(ctx, t, migrationsDir, "base.sql"))

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		user, err := repo.GetByLogin(ctx, "test@example.com")
		require.NoError(t, err)
		assert.Equal(t, &models.User{
			ID:            models.UserID(accountUUID),
			Login:         "test@example.com",
			PasswordHash:  []byte{0x12, 0x34},
			SecretKeyHash: []byte{0x45, 0x67},
		}, user)
	})

	t.Run("Fails_NotFound", func(t *testing.T) {
		t.Parallel()

		_, err := repo.GetByLogin(ctx, testutils.STRING)
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
	})
}

func TestUserRepository_CreateAccount(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	t.Cleanup(cancel)
	repo := repo.NewUserRepository(helpers.SetupDB(ctx, t, migrationsDir, "base.sql"))

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		userID, err := repo.CreateAccount(ctx, &models.User{
			Login:         "new@example.com",
			PasswordHash:  []byte("some-password"),
			SecretKeyHash: []byte("some-secret-key"),
		})
		require.NoError(t, err)
		assert.NoError(t, uuid.Validate(string(userID)))
	})

	t.Run("Fails_LoginUniqueConstraint", func(t *testing.T) {
		t.Parallel()

		_, err := repo.CreateAccount(ctx, &models.User{
			Login:         "test@example.com",
			PasswordHash:  []byte("some-password"),
			SecretKeyHash: []byte("some-secret-key"),
		})

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "23505", pgErr.Code)
	})
}
