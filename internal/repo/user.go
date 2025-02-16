package repo

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"

	domain "github.com/novoseltcev/passkeeper/internal/domains/user"
	"github.com/novoseltcev/passkeeper/internal/models"
)

type userRepository struct {
	db *sqlx.DB
}

type userInDB struct {
	ID            string `db:"uuid"`
	Login         string `db:"login"`
	PasswordHash  []byte `db:"password_hash"`
	SecretKeyHash []byte `db:"secret_key_hash"`
}

var _ domain.Repository = (*userRepository)(nil)

func NewUserRepository(db *sqlx.DB) *userRepository { // nolint: revive
	return &userRepository{db: db}
}

func (r *userRepository) GetByID(ctx context.Context, id models.UserID) (*models.User, error) {
	var user userInDB

	err := r.db.GetContext(ctx, &user, `
		SELECT uuid, login, password_hash, secret_key_hash
		FROM accounts
			WHERE uuid = $1
	`, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}

		return nil, err
	}

	return &models.User{
		ID:            models.UserID(user.ID),
		Login:         user.Login,
		PasswordHash:  user.PasswordHash,
		SecretKeyHash: user.SecretKeyHash,
	}, nil
}

func (r *userRepository) GetByLogin(ctx context.Context, login string) (*models.User, error) {
	var user userInDB

	err := r.db.GetContext(ctx, &user, `
		SELECT uuid, login, password_hash, secret_key_hash
		FROM accounts
			WHERE login = $1
	`, login)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}

		return nil, err
	}

	return &models.User{
		ID:            models.UserID(user.ID),
		Login:         user.Login,
		PasswordHash:  user.PasswordHash,
		SecretKeyHash: user.SecretKeyHash,
	}, nil
}

func (r *userRepository) CreateAccount(ctx context.Context, data *models.User) (models.UserID, error) {
	var id string

	err := r.db.GetContext(ctx, &id, `
		INSERT INTO accounts (login, password_hash, secret_key_hash, created_at)
		VALUES ($1, $2, $3, NOW())
		RETURNING uuid
	`, data.Login, data.PasswordHash, data.SecretKeyHash)
	if err != nil {
		return "", err
	}

	return models.UserID(id), nil
}
