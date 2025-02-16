package repo

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"

	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/models"
)

type secretRepository struct {
	db *sqlx.DB
}

type secretInDB struct {
	UUID          string `db:"uuid"`
	Name          string `db:"name"`
	Type          int    `db:"type"`
	EncryptedData []byte `db:"encrypted_data"`
	Owner         string `db:"owner_uuid"`
	SecretKeyHash string `db:"secret_key_hash"`
}

func (s secretInDB) ToDomain() *models.Secret {
	return &models.Secret{
		ID:    models.SecretID(s.UUID),
		Name:  s.Name,
		Type:  models.SecretType(s.Type),
		Data:  s.EncryptedData,
		Owner: &models.User{ID: models.UserID(s.Owner), SecretKeyHash: s.SecretKeyHash},
	}
}

var _ domain.Repository = (*secretRepository)(nil)

func NewSecretRepository(db *sqlx.DB) *secretRepository { // nolint: revive
	return &secretRepository{db: db}
}

func (r *secretRepository) GetOwner(ctx context.Context, ownerID models.UserID) (*models.User, error) {
	var owner userInDB

	err := r.db.GetContext(ctx, &owner, `
		SELECT uuid, login, password_hash, secret_key_hash
		FROM accounts
			WHERE uuid = $1
	`, ownerID)
	if err != nil {
		return nil, err
	}

	return &models.User{
		ID:            models.UserID(owner.ID),
		Login:         owner.Login,
		PasswordHash:  owner.PasswordHash,
		SecretKeyHash: owner.SecretKeyHash,
	}, nil
}

func (r *secretRepository) Get(ctx context.Context, id models.SecretID) (*models.Secret, error) {
	var secret secretInDB

	err := r.db.GetContext(ctx, &secret, `
		SELECT secrets.uuid, owner_uuid, name, type, encrypted_data, secret_key_hash
		FROM secrets
			JOIN accounts ON secrets.owner_uuid = accounts.uuid
				WHERE secrets.uuid = $1
	`, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrSecretNotFound
		}

		return nil, err
	}

	return secret.ToDomain(), nil
}

func (r *secretRepository) GetPage(
	ctx context.Context,
	ownerID models.UserID,
	limit, offset uint64,
) (*domain.Page[models.Secret], error) {
	var secrets []secretInDB

	err := r.db.SelectContext(ctx, &secrets, `
		SELECT uuid, owner_uuid, name, type, encrypted_data
		FROM secrets 
			WHERE owner_uuid = $1
				ORDER BY created_at DESC
					OFFSET $2 LIMIT $3
	`, ownerID, offset, limit)
	if err != nil {
		return nil, err
	}

	var total uint64
	if err = r.db.GetContext(ctx, &total, "SELECT COUNT(uuid) FROM secrets WHERE owner_uuid = $1", ownerID); err != nil {
		return nil, err
	}

	items := make([]models.Secret, len(secrets))
	for i, secret := range secrets {
		items[i] = *secret.ToDomain()
	}

	return domain.NewPage(items, total), nil
}

func (r *secretRepository) Create(ctx context.Context, data *models.Secret) (models.SecretID, error) {
	var id string

	err := r.db.GetContext(ctx, &id, `
		INSERT INTO secrets (name, type, encrypted_data, owner_uuid, created_at)
		VALUES ($1, $2, $3, $4, NOW())
		RETURNING uuid
	`, data.Name, data.Type, data.Data, data.Owner.ID)
	if err != nil {
		return "", err
	}

	return models.SecretID(id), nil
}

func (r *secretRepository) Update(ctx context.Context, id models.SecretID, data *models.Secret) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE secrets
		SET name = $2, encrypted_data = $3, updated_at = NOW()
		WHERE uuid = $1
	`, id, data.Name, data.Data)

	return err
}

func (r *secretRepository) Delete(ctx context.Context, id models.SecretID) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM secrets WHERE uuid = $1`, id)

	return err
}
