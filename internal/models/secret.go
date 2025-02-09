package models

type (
	SecretID   string
	SecretType int
	EncdData   []byte
)

const (
	SecretTypePwd SecretType = iota + 1
	SecretTypeTxt
	SecretTypeFile
	SecretTypeCard
)

type Secret struct {
	ID      SecretID
	Name    string
	Type    SecretType
	Content EncdData
	Meta    EncdData
	Owner   *User
}

func NewSecret(
	name string,
	secretType SecretType,
	content, meta []byte,
	owner *User,
) *Secret {
	return &Secret{
		Name:    name,
		Type:    secretType,
		Content: content,
		Meta:    meta,
		Owner:   owner,
	}
}
