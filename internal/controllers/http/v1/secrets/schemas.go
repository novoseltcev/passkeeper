package secrets

type PasswordSecretData struct {
	SecretKey string         `binding:"required"`
	Name      string         `binding:"required,min=4,max=32"`
	Login     string         `binding:"required"`
	Password  string         `binding:"required"`
	Meta      map[string]any `binding:"required"`
}

type CardSecretData struct {
	SecretKey string         `binding:"required"`
	Name      string         `binding:"required,min=4,max=32"`
	Number    string         `binding:"required,credit_card"`
	Holder    string         `json:"holder"`
	Exp       string         `binding:"required,datetime=01/02/2006"`
	CVV       string         `binding:"required,min=3,max=4,numeric" json:"cvv"`
	Meta      map[string]any `binding:"required"`
}
type TextSecretData struct {
	SecretKey string         `binding:"required"`
	Name      string         `binding:"required,min=4,max=32"`
	Content   string         `binding:"required"`
	Meta      map[string]any `binding:"required"`
}

type FileSecretData struct {
	SecretKey string         `binding:"required"`
	Name      string         `binding:"required,min=4,max=32"`
	Filename  string         `binding:"required"`
	Content   string         `binding:"required,hexadecimal"`
	Meta      map[string]any `binding:"required"`
}
