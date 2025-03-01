package repo_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/novoseltcev/passkeeper/internal/repo"
	"github.com/novoseltcev/passkeeper/pkg/jwtmanager"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
	"github.com/novoseltcev/passkeeper/pkg/testutils/helpers"
)

const (
	tokenUUID1 = "b3055e06-9300-4d6a-9df1-b95e6fefc916"
	tokenUUID2 = "e065b8b6-6d1e-4d1b-bf58-52b0df58f147"
)

func TestTokenRepository_Load(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	t.Cleanup(cancel)
	repo := repo.NewTokenRepository(helpers.SetupDB(ctx, t, migrationsDir, "base.sql"))

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		token, err := repo.Load(ctx, tokenUUID1)
		require.NoError(t, err)
		assert.Equal(t, tokenUUID1, token.ID)
		assert.Equal(t, accountUUID, token.Subject)
		assert.InDelta(t, time.Now().Add(time.Hour).Unix(), token.ExpiresAt.Unix(), float64(ctxTimeout))
	})

	t.Run("Fails_NotFound", func(t *testing.T) {
		t.Parallel()

		_, err := repo.Load(ctx, tokenUUID2)
		assert.ErrorIs(t, err, jwtmanager.ErrTokenNotFound)
	})

	t.Run("Fails_UUIDSyntaxError", func(t *testing.T) {
		t.Parallel()

		_, err := repo.Load(ctx, testutils.STRING)
		require.Error(t, err)

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "22P02", pgErr.Code)
	})
}

func TestTokenRepository_Store(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	t.Cleanup(cancel)
	repo := repo.NewTokenRepository(helpers.SetupDB(ctx, t, migrationsDir, "base.sql"))

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, repo.Store(ctx, jwtmanager.Token{
			ID:        uuid.NewString(),
			Subject:   accountUUID,
			ExpiresAt: time.Now().Add(time.Hour),
		}))
	})

	t.Run("Fails_FKConstraint", func(t *testing.T) {
		t.Parallel()

		err := repo.Store(ctx, jwtmanager.Token{
			ID:        uuid.NewString(),
			Subject:   uuid.NewString(),
			ExpiresAt: time.Now().Add(time.Hour),
		})
		require.Error(t, err)

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "23503", pgErr.Code)
	})
}
