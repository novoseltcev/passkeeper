package models

type (
	SecretID   string
	SecretType int
)

const (
	SecretTypePwd SecretType = iota + 1
	SecretTypeCard
	SecretTypeTxt
	SecretTypeFile
)

func (t SecretType) String() string {
	switch t {
	case SecretTypePwd:
		return "password"
	case SecretTypeCard:
		return "card"
	case SecretTypeTxt:
		return "text"
	case SecretTypeFile:
		return "file"
	default:
		return "unknown"
	}
}

type EncdData []byte

type Secret struct {
	ID    SecretID
	Name  string
	Type  SecretType
	Data  EncdData
	Owner *User
}

func NewSecret(
	name string,
	secretType SecretType,
	data EncdData,
	owner *User,
) *Secret {
	return &Secret{
		Name:  name,
		Type:  secretType,
		Data:  data,
		Owner: owner,
	}
}
