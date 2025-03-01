package secrets

type PasswordSecretData struct {
	Passphrase string         `binding:"required"`
	Name       string         `binding:"required,min=4,max=32"`
	Login      string         `binding:"required"`
	Password   string         `binding:"required"`
	Meta       map[string]any `binding:"required"`
}

type CardSecretData struct {
	Passphrase string         `binding:"required"`
	Name       string         `binding:"required,min=4,max=32"`
	Number     string         `binding:"required,credit_card"`
	Holder     string         `binding:""`
	Exp        string         `binding:"required,datetime=02/06"`
	CVV        string         `binding:"required,min=3,max=4,numeric" json:"cvv"`
	Meta       map[string]any `binding:"required"`
}
type TextSecretData struct {
	Passphrase string         `binding:"required"`
	Name       string         `binding:"required,min=4,max=32"`
	Content    string         `binding:"required"`
	Meta       map[string]any `binding:"required"`
}

type FileSecretData struct {
	Passphrase string         `binding:"required"`
	Name       string         `binding:"required,min=4,max=32"`
	Filename   string         `binding:"required"`
	Content    string         `binding:"required,hexadecimal"`
	Meta       map[string]any `binding:"required"`
}
