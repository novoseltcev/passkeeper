package secrets_test

import (
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/common/response"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/secrets"
)

func checkValidationErrors(t *testing.T, err error, errs []string) {
	t.Helper()

	require.Error(t, err)

	var vErr validator.ValidationErrors
	require.ErrorAs(t, err, &vErr)
	response := response.NewValidationError(vErr)

	assert.ElementsMatch(t, errs, response.Errors)
}

func TestValidation_PasswordSecretData_Fails(t *testing.T) {
	t.Parallel()
	validate := validator.New()
	validate.SetTagName("binding")

	tests := []struct {
		name string
		data *secrets.PasswordSecretData
		errs []string
	}{
		{
			name: "empty",
			data: &secrets.PasswordSecretData{},
			errs: []string{
				"Field validation for 'Passphrase' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Login' failed on the 'required' tag",
				"Field validation for 'Password' failed on the 'required' tag",
				"Field validation for 'Meta' failed on the 'required' tag",
			},
		},
		{
			name: "len(name) < 4",
			data: &secrets.PasswordSecretData{
				Name:       "123",
				Passphrase: " ",
				Login:      " ",
				Password:   " ",
				Meta:       map[string]any{},
			},
			errs: []string{"Field validation for 'Name' failed on the 'min' tag"},
		},
		{
			name: "len(name) > 32",
			data: &secrets.PasswordSecretData{
				Name:       strings.Repeat("a", 33),
				Passphrase: " ",
				Login:      " ",
				Password:   " ",
				Meta:       map[string]any{},
			},
			errs: []string{"Field validation for 'Name' failed on the 'max' tag"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkValidationErrors(t, validate.Struct(tt.data), tt.errs)
		})
	}
}

func TestValidation_CardSecretData_Fails(t *testing.T) {
	t.Parallel()
	validate := validator.New()
	validate.SetTagName("binding")

	tests := []struct {
		name string
		data *secrets.CardSecretData
		errs []string
	}{
		{
			name: "empty fields",
			data: &secrets.CardSecretData{},
			errs: []string{
				"Field validation for 'Passphrase' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Number' failed on the 'required' tag",
				"Field validation for 'Exp' failed on the 'required' tag",
				"Field validation for 'CVV' failed on the 'required' tag",
				"Field validation for 'Meta' failed on the 'required' tag",
			},
		},
		{
			name: "len(name < 4, len(cvv) < 3, number is not credit card, exp is not date",
			data: &secrets.CardSecretData{
				Name:       "123",
				CVV:        "12",
				Number:     "some",
				Exp:        "abc",
				Passphrase: " ",
				Meta:       map[string]any{},
			},
			errs: []string{
				"Field validation for 'Name' failed on the 'min' tag",
				"Field validation for 'CVV' failed on the 'min' tag",
				"Field validation for 'Number' failed on the 'credit_card' tag",
				"Field validation for 'Exp' failed on the 'datetime' tag",
			},
		},
		{
			name: "len(name) > 32, len(cvv) > 4, exp mismatch layout",
			data: &secrets.CardSecretData{
				Name:       strings.Repeat("a", 33),
				CVV:        "12345",
				Exp:        "08/12/2025 12:00:00",
				Passphrase: " ",
				Number:     "4111111111111111",
				Meta:       map[string]any{},
			},
			errs: []string{
				"Field validation for 'Name' failed on the 'max' tag",
				"Field validation for 'CVV' failed on the 'max' tag",
				"Field validation for 'Exp' failed on the 'datetime' tag",
			},
		},
		{
			name: "cvv is not numeric",
			data: &secrets.CardSecretData{
				CVV:        "12a",
				Passphrase: " ",
				Name:       "test",
				Number:     "4111111111111111",
				Exp:        "12/25",
				Meta:       map[string]any{},
			},
			errs: []string{"Field validation for 'CVV' failed on the 'numeric' tag"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkValidationErrors(t, validate.Struct(tt.data), tt.errs)
		})
	}
}

func TestValidation_TextSecretData_Fails(t *testing.T) {
	t.Parallel()
	validate := validator.New()
	validate.SetTagName("binding")

	tests := []struct {
		name string
		data *secrets.TextSecretData
		errs []string
	}{
		{
			name: "empty",
			data: &secrets.TextSecretData{},
			errs: []string{
				"Field validation for 'Passphrase' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Content' failed on the 'required' tag",
				"Field validation for 'Meta' failed on the 'required' tag",
			},
		},
		{
			name: "len(name) < 4",
			data: &secrets.TextSecretData{
				Name:       "123",
				Passphrase: " ",
				Content:    " ",
				Meta:       map[string]any{},
			},
			errs: []string{"Field validation for 'Name' failed on the 'min' tag"},
		},
		{
			name: "len(name) > 32",
			data: &secrets.TextSecretData{
				Name:       strings.Repeat("a", 33),
				Passphrase: " ",
				Content:    " ",
				Meta:       map[string]any{},
			},
			errs: []string{"Field validation for 'Name' failed on the 'max' tag"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkValidationErrors(t, validate.Struct(tt.data), tt.errs)
		})
	}
}

func TestValidation_FileSecretData_Fails(t *testing.T) {
	t.Parallel()
	validate := validator.New()
	validate.SetTagName("binding")

	tests := []struct {
		name string
		data *secrets.FileSecretData
		errs []string
	}{
		{
			name: "empty",
			data: &secrets.FileSecretData{},
			errs: []string{
				"Field validation for 'Passphrase' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Filename' failed on the 'required' tag",
				"Field validation for 'Content' failed on the 'required' tag",
				"Field validation for 'Meta' failed on the 'required' tag",
			},
		},
		{
			name: "len(name) < 4, content is not hexadecimal",
			data: &secrets.FileSecretData{
				Name:       "123",
				Passphrase: " ",
				Filename:   " ",
				Content:    " ",
				Meta:       map[string]any{},
			},
			errs: []string{
				"Field validation for 'Name' failed on the 'min' tag",
				"Field validation for 'Content' failed on the 'hexadecimal' tag",
			},
		},
		{
			name: "len(name) > 32",
			data: &secrets.FileSecretData{
				Name:       strings.Repeat("a", 33),
				Passphrase: " ",
				Filename:   " ",
				Content:    "74657374",
				Meta:       map[string]any{},
			},
			errs: []string{"Field validation for 'Name' failed on the 'max' tag"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			checkValidationErrors(t, validate.Struct(tt.data), tt.errs)
		})
	}
}
