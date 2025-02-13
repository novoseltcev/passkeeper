package models

type (
	UserID string
	User   struct {
		ID            UserID
		Login         string
		PasswordHash  []byte
		SecretKeyHash []byte
	}
)

func NewUser(login string, pwdHash, secretKeyHash []byte) *User {
	return &User{
		Login:         login,
		PasswordHash:  pwdHash,
		SecretKeyHash: secretKeyHash,
	}
}
