package repo_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/models"
	"github.com/novoseltcev/passkeeper/internal/repo"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
	"github.com/novoseltcev/passkeeper/pkg/testutils/helpers"
)

const (
	secretUUID1 = "a6a3097b-7b03-4f3c-9686-7264a163b34d"
	secretUUID2 = "fd537d2d-a926-4027-b76f-0148a384a7b1"
	secretUUID3 = "87c7b7f3-fb64-4206-849c-a40f98665961"
	secretUUID4 = "e58bbd83-6068-4bfd-a769-36b2962c759a"
)

func TestSecretRepository_GetOwner(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	t.Cleanup(cancel)
	repo := repo.NewSecretRepository(helpers.SetupDB(ctx, t, migrationsDir, "base.sql"))

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		user, err := repo.GetOwner(ctx, models.UserID(accountUUID))
		require.NoError(t, err)
		assert.Equal(t, &models.User{
			ID:             models.UserID(accountUUID),
			Login:          "test@example.com",
			PasswordHash:   "1234",
			PassphraseHash: "4567",
		}, user)
	})

	t.Run("Fails_NotFound", func(t *testing.T) {
		t.Parallel()

		_, err := repo.GetOwner(ctx, models.UserID(uuid.NewString()))
		assert.ErrorIs(t, err, sql.ErrNoRows)
	})

	t.Run("Fails_UUIDSyntaxError", func(t *testing.T) {
		t.Parallel()

		_, err := repo.GetOwner(ctx, models.UserID(testutils.STRING))
		require.Error(t, err)

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "22P02", pgErr.Code)
	})
}

func TestSecretRepository_Get(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	t.Cleanup(cancel)
	repo := repo.NewSecretRepository(helpers.SetupDB(ctx, t, migrationsDir, "base.sql"))

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		secret, err := repo.Get(ctx, models.SecretID(secretUUID1))
		require.NoError(t, err)
		assert.Equal(t, &models.Secret{
			ID:   models.SecretID(secretUUID1),
			Name: "some",
			Type: models.SecretType(2),
			Data: []byte{0xde, 0xff, 0x12, 0x34},
			Owner: &models.User{
				ID:             models.UserID(accountUUID),
				PassphraseHash: "4567",
			},
		}, secret)
	})

	t.Run("Fails_NotFound", func(t *testing.T) {
		t.Parallel()

		_, err := repo.Get(ctx, models.SecretID(uuid.NewString()))
		assert.ErrorIs(t, err, domain.ErrSecretNotFound)
	})

	t.Run("Fails_UUIDSyntaxError", func(t *testing.T) {
		t.Parallel()

		_, err := repo.Get(ctx, testutils.STRING)

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "22P02", pgErr.Code)
	})
}

func TestSecretRepository_GetPage(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	t.Cleanup(cancel)
	repo := repo.NewSecretRepository(helpers.SetupDB(ctx, t, migrationsDir, "base.sql"))

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		page, err := repo.GetPage(ctx, models.UserID(accountUUID), 2, 0)
		require.NoError(t, err)
		assert.Equal(t, uint64(3), page.Total)
		assert.Equal(t, []models.Secret{
			{
				ID:    models.SecretID(secretUUID1),
				Name:  "some",
				Type:  models.SecretType(2),
				Data:  []byte{0xde, 0xff, 0x12, 0x34},
				Owner: &models.User{ID: models.UserID(accountUUID)},
			},
			{
				ID:    models.SecretID(secretUUID2),
				Name:  "some1",
				Type:  models.SecretType(1),
				Data:  []byte{0xab, 0xc1},
				Owner: &models.User{ID: models.UserID(accountUUID)},
			},
		}, page.Items)
	})

	t.Run("Fails_NotFound", func(t *testing.T) {
		t.Parallel()

		page, err := repo.GetPage(ctx, models.UserID(uuid.NewString()), 0, 2)
		require.NoError(t, err)
		assert.Equal(t, uint64(0), page.Total)
		assert.Equal(t, []models.Secret{}, page.Items)
	})

	t.Run("Fails_UUIDSyntaxError", func(t *testing.T) {
		t.Parallel()

		_, err := repo.GetPage(ctx, models.UserID(testutils.STRING), 0, 2)
		require.Error(t, err)

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "22P02", pgErr.Code)
	})
}

func TestSecretRepository_Create(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	t.Cleanup(cancel)
	repo := repo.NewSecretRepository(helpers.SetupDB(ctx, t, migrationsDir, "base.sql"))

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		id, err := repo.Create(ctx, &models.Secret{
			Name:  "some",
			Type:  models.SecretTypePwd,
			Data:  []byte("some-data"),
			Owner: &models.User{ID: models.UserID(accountUUID)},
		})
		require.NoError(t, err)
		assert.NoError(t, uuid.Validate(string(id)))
	})

	t.Run("Fails_FKConstraint", func(t *testing.T) {
		t.Parallel()

		_, err := repo.Create(ctx, &models.Secret{
			Name:  "some",
			Type:  models.SecretTypePwd,
			Data:  []byte("some-data"),
			Owner: &models.User{ID: models.UserID(uuid.NewString())},
		})
		require.Error(t, err)

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "23503", pgErr.Code)
	})
}

func TestSecretRepository_Update(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	t.Cleanup(cancel)
	repo := repo.NewSecretRepository(helpers.SetupDB(ctx, t, migrationsDir, "base.sql"))

	t.Run("Success_Updated", func(t *testing.T) {
		t.Parallel()

		before, err := repo.Get(ctx, models.SecretID(secretUUID1))
		require.NoError(t, err)
		require.NotEqual(t, "brand new updated", before.Name)
		require.NotEqual(t, []byte("new-data"), before.Data)

		require.NoError(t, repo.Update(ctx, models.SecretID(secretUUID1), &models.Secret{
			Name: "brand new updated",
			Data: []byte("new-data"),
		}))

		after, err := repo.Get(ctx, models.SecretID(secretUUID1))
		require.NoError(t, err)
		assert.Equal(t, "brand new updated", after.Name)
		assert.Equal(t, []byte("new-data"), []byte(after.Data))
	})

	t.Run("Success_NotFound", func(t *testing.T) {
		t.Parallel()
		_, err := repo.Get(ctx, models.SecretID(uuid.NewString()))
		require.ErrorIs(t, err, domain.ErrSecretNotFound)

		assert.NoError(t, repo.Update(ctx, models.SecretID(uuid.NewString()), &models.Secret{}))
	})

	t.Run("Fails_UUIDSyntaxError", func(t *testing.T) {
		t.Parallel()

		err := repo.Update(ctx, models.SecretID(testutils.STRING), &models.Secret{})
		require.Error(t, err)

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "22P02", pgErr.Code)
	})
}

func TestSecretRepository_Delete(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	t.Cleanup(cancel)
	repo := repo.NewSecretRepository(helpers.SetupDB(ctx, t, migrationsDir, "base.sql"))

	t.Run("Success_Deleted", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, repo.Delete(ctx, models.SecretID(secretUUID1)))

		_, err := repo.Get(ctx, models.SecretID(secretUUID1))
		assert.ErrorIs(t, err, domain.ErrSecretNotFound)
	})

	t.Run("Success_NotFound", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, repo.Delete(ctx, models.SecretID(uuid.NewString())))
	})

	t.Run("Fails_UUIDSyntaxError", func(t *testing.T) {
		t.Parallel()

		err := repo.Delete(ctx, models.SecretID(testutils.STRING))
		require.Error(t, err)

		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		assert.Equal(t, "22P02", pgErr.Code)
	})
}
