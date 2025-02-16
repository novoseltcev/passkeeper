package models

type (
	UserID string
	User   struct {
		ID            UserID
		Login         string
		PasswordHash  string
		SecretKeyHash string
	}
)

func NewUser(login, pwdHash, secretKeyHash string) *User {
	return &User{
		Login:         login,
		PasswordHash:  pwdHash,
		SecretKeyHash: secretKeyHash,
	}
}
