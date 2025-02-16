package secrets_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steinfletcher/apitest"
	"go.uber.org/mock/gomock"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/secrets"
	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/domains/secrets/mocks"
	"github.com/novoseltcev/passkeeper/internal/models"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
)

var secretTypes = []models.SecretType{
	models.SecretTypePwd,
	models.SecretTypeCard,
	models.SecretTypeTxt,
	models.SecretTypeFile,
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	t.Run("password", func(t *testing.T) {
		t.Parallel()
		root := gin.Default()
		service := mocks.NewMockService(ctrl)
		secrets.AddRoutes(&root.RouterGroup, service, guardMock)

		service.EXPECT().
			Update(gomock.Any(), testID, testOwnerID, testPassphrase, testName, &domain.PasswordData{
				Login:    testLogin,
				Password: testPassword,
				Meta:     testMetaMap,
			}).
			Return(nil)

		apitest.Handler(root.Handler()).
			Debug().
			Putf("/secrets/password/%s", testID).
			Bodyf(`
			{
				"passphrase":"%s",
				"name":"%s",
				"login":"%s",
				"password":"%s",
				"meta":%s
			}`, testPassphrase, testName, testLogin, testPassword, testMeta).
			Expect(t).
			Status(http.StatusNoContent).
			End()
	})

	t.Run("card", func(t *testing.T) {
		t.Parallel()
		root := gin.Default()
		service := mocks.NewMockService(ctrl)
		secrets.AddRoutes(&root.RouterGroup, service, guardMock)

		service.EXPECT().
			Update(gomock.Any(), testID, testOwnerID, testPassphrase, testName, &domain.CardData{
				Number: testCard,
				Holder: testHolder,
				Exp:    testExp,
				CVV:    testCVV,
				Meta:   testMetaMap,
			}).
			Return(nil)

		apitest.Handler(root.Handler()).
			Debug().
			Putf("/secrets/card/%s", testID).
			Bodyf(`
			{
				"passphrase":"%s",
				"name":"%s",
				"number":"%s",
				"holder":"%s",
				"exp":"%s",
				"cvv":"%s",
				"meta":%s
			}`, testPassphrase, testName, testCard, testHolder, testExp, testCVV, testMeta).
			Expect(t).
			Status(http.StatusNoContent).
			End()
	})

	t.Run("text", func(t *testing.T) {
		t.Parallel()
		root := gin.Default()
		service := mocks.NewMockService(ctrl)
		secrets.AddRoutes(&root.RouterGroup, service, guardMock)

		service.EXPECT().
			Update(gomock.Any(), testID, testOwnerID, testPassphrase, testName, &domain.TextData{
				Content: testutils.STRING,
				Meta:    testMetaMap,
			}).
			Return(nil)

		apitest.Handler(root.Handler()).
			Debug().
			Putf("/secrets/text/%s", testID).
			Bodyf(`
			{
				"passphrase":"%s",
				"name":"%s",
				"content":"%s",
				"meta":%s
			}`, testPassphrase, testName, testutils.STRING, testMeta).
			Expect(t).
			Status(http.StatusNoContent).
			End()
	})

	t.Run("file", func(t *testing.T) {
		t.Parallel()
		root := gin.Default()
		service := mocks.NewMockService(ctrl)
		secrets.AddRoutes(&root.RouterGroup, service, guardMock)

		service.EXPECT().
			Update(gomock.Any(), testID, testOwnerID, testPassphrase, testName, &domain.FileData{
				Filename: testutils.STRING,
				Content:  testHex,
				Meta:     testMetaMap,
			}).
			Return(nil)

		apitest.Handler(root.Handler()).
			Debug().
			Putf("/secrets/file/%s", testID).
			Bodyf(`
			{
				"passphrase":"%s",
				"name":"%s",
				"filename":"%s",
				"content":"%s",
				"meta":%s
			}`, testPassphrase, testName, testutils.STRING, testHex, testMeta).
			Expect(t).
			Status(http.StatusNoContent).
			End()
	})
}

var defaultUpdateData = map[models.SecretType]string{
	models.SecretTypePwd: `
	{
		"passphrase":"passphrase",
		"name":"test",
		"login":"login",
		"password":"p@ssw0rd",
		"meta":{}
	}`,
	models.SecretTypeCard: `
	{
		"passphrase":"passphrase",
		"name":"test",
		"number":"4111111111111111",
		"holder":"John Doe",
		"exp":"08/12/2025",
		"cvv":"123",
		"meta":{}
	}`,
	models.SecretTypeTxt: `
	{
		"passphrase":"passphrase",
		"name":"test",
		"content":"string",
		"meta":{}
	}`,
	models.SecretTypeFile: `
	{
		"passphrase":"passphrase",
		"name":"test",
		"filename":"string",
		"content":"74657374",
		"meta":{}
	}`,
}

func TestUpdate_Fails_Update(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	tests := []struct {
		name   string
		err    error
		status int
	}{
		{
			name:   "not found",
			err:    domain.ErrSecretNotFound,
			status: http.StatusNotFound,
		},
		{
			name:   "not mine",
			err:    domain.ErrAnotherOwner,
			status: http.StatusForbidden,
		},
		{
			name:   "invalid secret type",
			err:    domain.ErrInvalidSecretType,
			status: http.StatusConflict,
		},
		{
			name:   "other",
			err:    testutils.Err,
			status: http.StatusInternalServerError,
		},
	}

	for _, secretType := range secretTypes {
		for _, tt := range tests {
			testName := fmt.Sprintf("%s-%s", secretType, tt.name)
			t.Run(testName, func(t *testing.T) {
				t.Parallel()
				root := gin.Default()
				service := mocks.NewMockService(ctrl)
				secrets.AddRoutes(&root.RouterGroup, service, guardMock)

				service.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(tt.err)

				apitest.New(testName).
					Handler(root.Handler()).
					Debug().
					Putf("/secrets/%s/%s", secretType.String(), testID).
					Body(defaultUpdateData[secretType]).
					Expect(t).
					Status(tt.status).
					End()
			})
		}
	}
}

func TestUpdatePassword_Fails_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		status int
		errs   []string
	}{
		{
			name:   "invalid json body",
			body:   `{`,
			status: http.StatusBadRequest,
		},
		{
			name:   "empty",
			body:   `{}`,
			status: http.StatusUnprocessableEntity,
			errs: []string{
				"Field validation for 'Passphrase' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Login' failed on the 'required' tag",
				"Field validation for 'Password' failed on the 'required' tag",
				"Field validation for 'Meta' failed on the 'required' tag",
			},
		},
		{
			name: "empty fields",
			body: `
			{
				"passphrase":"",
				"name":"",
				"login":"",
				"password":"",
				"meta":{}
			}`,
			status: http.StatusUnprocessableEntity,
			errs: []string{
				"Field validation for 'Passphrase' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Login' failed on the 'required' tag",
				"Field validation for 'Password' failed on the 'required' tag",
			},
		},
		{
			name: "len(name) < 4",
			body: `
			{
				"name":"123",
				"passphrase":" ",
				"login":" ",
				"password":" ",
				"meta":{}
			}`,
			status: http.StatusUnprocessableEntity,
			errs:   []string{"Field validation for 'Name' failed on the 'min' tag"},
		},
		{
			name: "len(name) > 32",
			body: fmt.Sprintf(`
			{
				"name":"%s",
				"passphrase":" ",
				"login":" ",
				"password":" ",
				"meta":{}
			}`, strings.Repeat("a", 33)),
			status: http.StatusUnprocessableEntity,
			errs:   []string{"Field validation for 'Name' failed on the 'max' tag"},
		},
		{
			name:   "meta is string",
			body:   `{"meta":"{}"}`,
			status: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := gin.Default()
			secrets.AddRoutes(&root.RouterGroup, nil, guardMock)

			result := apitest.New(tt.name).
				Handler(root.Handler()).
				Debug().
				Putf("/secrets/password/%s", testID).
				Body(tt.body).
				Expect(t).
				Status(tt.status).
				End()

			if len(tt.errs) > 0 {
				checkErrors(t, result, tt.errs)
			}
		})
	}
}

func TestUpdateCard_Fails_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		status int
		errs   []string
	}{
		{
			name:   "invalid json body",
			body:   `{`,
			status: http.StatusBadRequest,
		},
		{
			name:   "empty",
			body:   `{}`,
			status: http.StatusUnprocessableEntity,
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
			name:   "meta is string",
			body:   `{"meta":"{}"}`,
			status: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := gin.Default()
			secrets.AddRoutes(&root.RouterGroup, nil, guardMock)

			result := apitest.New(tt.name).
				Handler(root.Handler()).
				Debug().
				Putf("/secrets/card/%s", testID).
				Body(tt.body).
				Expect(t).
				Status(tt.status).
				End()

			if len(tt.errs) > 0 {
				checkErrors(t, result, tt.errs)
			}
		})
	}
}

func TestUpdateText_Fails_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		status int
		errs   []string
	}{
		{
			name:   "invalid json body",
			body:   `{`,
			status: http.StatusBadRequest,
		},
		{
			name:   "empty",
			body:   `{}`,
			status: http.StatusUnprocessableEntity,
			errs: []string{
				"Field validation for 'Passphrase' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Content' failed on the 'required' tag",
				"Field validation for 'Meta' failed on the 'required' tag",
			},
		},
		{
			name:   "meta is string",
			body:   `{"meta":"{}"}`,
			status: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := gin.Default()
			secrets.AddRoutes(&root.RouterGroup, nil, guardMock)

			result := apitest.New(tt.name).
				Handler(root.Handler()).
				Debug().
				Putf("/secrets/text/%s", testID).
				Body(tt.body).
				Expect(t).
				Status(tt.status).
				End()

			if len(tt.errs) > 0 {
				checkErrors(t, result, tt.errs)
			}
		})
	}
}

func TestUpdateFile_Fails_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		status int
		errs   []string
	}{
		{
			name:   "invalid json body",
			body:   `{`,
			status: http.StatusBadRequest,
		},
		{
			name:   "empty",
			body:   `{}`,
			status: http.StatusUnprocessableEntity,
			errs: []string{
				"Field validation for 'Passphrase' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Filename' failed on the 'required' tag",
				"Field validation for 'Content' failed on the 'required' tag",
				"Field validation for 'Meta' failed on the 'required' tag",
			},
		},
		{
			name:   "meta is string",
			body:   `{"meta":"{}"}`,
			status: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := gin.Default()
			secrets.AddRoutes(&root.RouterGroup, nil, guardMock)

			result := apitest.New(tt.name).
				Handler(root.Handler()).
				Debug().
				Putf("/secrets/file/%s", testID).
				Body(tt.body).
				Expect(t).
				Status(tt.status).
				End()

			if len(tt.errs) > 0 {
				checkErrors(t, result, tt.errs)
			}
		})
	}
}
