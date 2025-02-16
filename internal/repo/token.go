package repo

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/novoseltcev/passkeeper/pkg/jwtmanager"
)

type tokenInDB struct {
	ID        string    `db:"uuid"`
	UserID    string    `db:"account_uuid"`
	ExpiresAt time.Time `db:"expires_at"`
}

type tokenRepository struct {
	db *sqlx.DB
}

var _ jwtmanager.TokenStorager = (*tokenRepository)(nil)

func NewTokenRepository(db *sqlx.DB) *tokenRepository { // nolint: revive
	return &tokenRepository{db: db}
}

func (r *tokenRepository) Load(ctx context.Context, id string) (*jwtmanager.Token, error) {
	var token tokenInDB

	err := r.db.GetContext(ctx, &token, `
		SELECT uuid, account_uuid, expires_at
		FROM sessions
			WHERE uuid = $1 AND expires_at > NOW()
	`, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, jwtmanager.ErrTokenNotFound
		}

		return nil, err
	}

	return &jwtmanager.Token{
		ID:        token.ID,
		Subject:   token.UserID,
		ExpiresAt: token.ExpiresAt,
	}, nil
}

func (r *tokenRepository) Store(ctx context.Context, token jwtmanager.Token) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sessions (uuid, account_uuid, created_at, expires_at)
		VALUES ($1, $2, NOW(), $3)
	`, token.ID, token.Subject, token.ExpiresAt)

	return err
}
