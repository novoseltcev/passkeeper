package secrets

import "github.com/novoseltcev/passkeeper/internal/models"

type PasswordData struct {
	Login    string         `json:"login"`
	Password string         `json:"password"`
	Meta     map[string]any `json:"meta"`
}

func (p PasswordData) SecretType() models.SecretType {
	return models.SecretTypePwd
}

type CardData struct {
	Number string         `json:"number"`
	Holder string         `json:"holder"`
	Exp    string         `json:"exp"`
	CVV    string         `json:"cvv"`
	Meta   map[string]any `json:"meta"`
}

func (c CardData) SecretType() models.SecretType {
	return models.SecretTypeCard
}

type TextData struct {
	Content string         `json:"content"`
	Meta    map[string]any `json:"meta"`
}

func (t TextData) SecretType() models.SecretType {
	return models.SecretTypeTxt
}

type FileData struct {
	Filename string         `json:"filename"`
	Content  string         `json:"content"`
	Meta     map[string]any `json:"meta"`
}

func (f FileData) SecretType() models.SecretType {
	return models.SecretTypeFile
}
