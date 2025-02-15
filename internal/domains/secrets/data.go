package secrets

import (
	"fmt"

	"github.com/novoseltcev/passkeeper/internal/models"
)

type PasswordData struct {
	Login    string
	Password string
	Meta     map[string]any
}

func (p PasswordData) ToString() string {
	return fmt.Sprintf(`{"login":"%s","password":"%s","meta":"%s"}`, p.Login, p.Password, p.Meta)
}

func (p PasswordData) SecretType() models.SecretType {
	return models.SecretTypePwd
}

type CardData struct {
	Number string
	Holder string
	Exp    string
	CVV    string
	Meta   map[string]any
}

func (c CardData) ToString() string {
	return fmt.Sprintf(
		`{"number":"%s","holder":"%s","exp":"%s","cvv":"%s","meta":"%s"}`,
		c.Number, c.Holder, c.Exp, c.CVV, c.Meta,
	)
}

func (c CardData) SecretType() models.SecretType {
	return models.SecretTypeCard
}

type TextData struct {
	Content string
	Meta    map[string]any
}

func (t TextData) ToString() string {
	return fmt.Sprintf(`{"content":"%s","meta":"%s"}`, t.Content, t.Meta)
}

func (t TextData) SecretType() models.SecretType {
	return models.SecretTypeTxt
}

type FileData struct {
	Filename string
	Content  string
	Meta     map[string]any
}

func (f FileData) ToString() string {
	return fmt.Sprintf(`{"filename":"%s","content":"%s","meta":"%s"}`, f.Filename, f.Content, f.Meta)
}

func (f FileData) SecretType() models.SecretType {
	return models.SecretTypeFile
}
