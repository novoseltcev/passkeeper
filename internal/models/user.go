package models

type (
	UserID string
	User   struct {
		ID             UserID
		Login          string
		PasswordHash   string
		PassphraseHash string
	}
)

func NewUser(login, pwdHash, passphraseHash string) *User {
	return &User{
		Login:          login,
		PasswordHash:   pwdHash,
		PassphraseHash: passphraseHash,
	}
}
