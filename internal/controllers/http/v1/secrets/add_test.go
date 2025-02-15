package secrets_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steinfletcher/apitest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/common/response"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/secrets"
	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/domains/secrets/mocks"
	"github.com/novoseltcev/passkeeper/internal/models"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
)

var (
	testSecretKey = "secret-key"
	testLogin     = "login"
	testPassword  = "p@ssw0rd"
	testMeta      = `{"key":"value"}`
	testCard      = "4111111111111111"
	testHolder    = "John Doe"
	testExp       = "08/12/2025"
	testCVV       = "123"
)

var testMetaMap = map[string]any{"key": "value"}

func TestAdd(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	t.Run("password", func(t *testing.T) {
		t.Parallel()
		root := gin.Default()
		service := mocks.NewMockService(ctrl)
		secrets.AddRoutes(&root.RouterGroup, service, guardMock)

		service.EXPECT().
			Create(gomock.Any(), testOwnerID, testSecretKey, testName, &domain.PasswordData{
				Login:    testLogin,
				Password: testPassword,
				Meta:     testMetaMap,
			}).
			Return(testID, nil)

		apitest.Handler(root.Handler()).
			Debug().
			Post("/secrets/password").
			Bodyf(`
			{
				"secretKey":"%s",
				"name":"%s",
				"login":"%s",
				"password":"%s",
				"meta":%s
			}`, testSecretKey, testName, testLogin, testPassword, testMeta).
			Expect(t).
			Status(http.StatusCreated).
			Bodyf(`{"success":true, "result": {"id":"%s"}}`, testID).
			End()
	})

	t.Run("card", func(t *testing.T) {
		t.Parallel()
		root := gin.Default()
		service := mocks.NewMockService(ctrl)
		secrets.AddRoutes(&root.RouterGroup, service, guardMock)

		service.EXPECT().
			Create(gomock.Any(), testOwnerID, testSecretKey, testName, &domain.CardData{
				Number: testCard,
				Holder: testHolder,
				Exp:    testExp,
				CVV:    testCVV,
				Meta:   testMetaMap,
			}).
			Return(testID, nil)

		apitest.Handler(root.Handler()).
			Debug().
			Post("/secrets/card").
			Bodyf(`
			{
				"secretKey":"%s",
				"name":"%s",
				"number":"%s",
				"holder":"%s",
				"exp":"%s",
				"cvv":"%s",
				"meta":%s
			}`, testSecretKey, testName, testCard, testHolder, testExp, testCVV, testMeta).
			Expect(t).
			Status(http.StatusCreated).
			Bodyf(`{"success":true, "result": {"id":"%s"}}`, testID).
			End()
	})

	t.Run("text", func(t *testing.T) {
		t.Parallel()
		root := gin.Default()
		service := mocks.NewMockService(ctrl)
		secrets.AddRoutes(&root.RouterGroup, service, guardMock)

		service.EXPECT().
			Create(gomock.Any(), testOwnerID, testSecretKey, testName, &domain.TextData{
				Content: testutils.STRING,
				Meta:    testMetaMap,
			}).
			Return(testID, nil)

		apitest.Handler(root.Handler()).
			Debug().
			Post("/secrets/text").
			Bodyf(`
			{
				"secretKey":"%s",
				"name":"%s",
				"content":"%s",
				"meta":%s
			}`, testSecretKey, testName, testutils.STRING, testMeta).
			Expect(t).
			Status(http.StatusCreated).
			Bodyf(`{"success":true, "result": {"id":"%s"}}`, testID).
			End()
	})

	t.Run("file", func(t *testing.T) {
		t.Parallel()
		root := gin.Default()
		service := mocks.NewMockService(ctrl)
		secrets.AddRoutes(&root.RouterGroup, service, guardMock)

		service.EXPECT().
			Create(gomock.Any(), testOwnerID, testSecretKey, testName, &domain.FileData{
				Filename: testutils.STRING,
				Content:  testHex,
				Meta:     testMetaMap,
			}).
			Return(testID, nil)

		apitest.Handler(root.Handler()).
			Debug().
			Post("/secrets/file").
			Bodyf(`
			{
				"secretKey":"%s",
				"name":"%s",
				"filename":"%s",
				"content":"%s",
				"meta":%s
			}`, testSecretKey, testName, testutils.STRING, testHex, testMeta).
			Expect(t).
			Status(http.StatusCreated).
			Bodyf(`{"success":true, "result": {"id":"%s"}}`, testID).
			End()
	})
}

var defaultAddData = map[models.SecretType]string{
	models.SecretTypePwd: `
	{
		"secretKey":"secret-key",
		"name":"test",
		"login":"login",
		"password":"p@ssw0rd",
		"meta":{}
	}`,
	models.SecretTypeCard: `
	{
		"secretKey":"secret-key",
		"name":"test",
		"number":"4111111111111111",
		"holder":"John Doe",
		"exp":"08/12/2025",
		"cvv":"123",
		"meta":{}
	}`,
	models.SecretTypeTxt: `
	{
		"secretKey":"secret-key",
		"name":"test",
		"content":"string",
		"meta":{}
	}`,
	models.SecretTypeFile: `
	{
		"secretKey":"secret-key",
		"name":"test",
		"filename":"string",
		"content":"74657374",
		"meta":{}
	}`,
}

func TestAdd_Fails_Create(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	tests := []struct {
		name   string
		err    error
		status int
	}{
		{
			name:   "invalid secret key",
			err:    domain.ErrInvalidSecretKey,
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
					Create(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return("", tt.err)

				apitest.New(testName).
					Handler(root.Handler()).
					Debug().
					Postf("/secrets/%s", secretType.String()).
					Body(defaultAddData[secretType]).
					Expect(t).
					Status(tt.status).
					End()
			})
		}
	}
}

func TestAddPassword_Fails_Validate(t *testing.T) {
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
				"Field validation for 'SecretKey' failed on the 'required' tag",
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
				"secretKey":"",
				"name":"",
				"login":"",
				"password":"",
				"meta":{}
			}`,
			status: http.StatusUnprocessableEntity,
			errs: []string{
				"Field validation for 'SecretKey' failed on the 'required' tag",
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
				"secretKey":" ",
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
				"secretKey":" ",
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
				Post("/secrets/password").
				Body(tt.body).
				Expect(t).
				Status(tt.status).
				End()

			if len(tt.errs) > 0 {
				var response response.Response[any]
				result.JSON(&response)

				require.False(t, response.Success)
				require.Nil(t, response.Result)
				assert.ElementsMatch(t, tt.errs, response.Errors)
			}
		})
	}
}

func TestAddCard_Fails_Validate(t *testing.T) {
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
				"Field validation for 'SecretKey' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Number' failed on the 'required' tag",
				"Field validation for 'Exp' failed on the 'required' tag",
				"Field validation for 'CVV' failed on the 'required' tag",
				"Field validation for 'Meta' failed on the 'required' tag",
			},
		},
		{
			name: "empty fields",
			body: `
			{
				"secretKey":"",
				"name":"",
				"number":"",
				"holder":"",
				"exp":"",
				"meta":{}
			}`,
			status: http.StatusUnprocessableEntity,
			errs: []string{
				"Field validation for 'SecretKey' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Number' failed on the 'required' tag",
				"Field validation for 'Exp' failed on the 'required' tag",
				"Field validation for 'CVV' failed on the 'required' tag",
			},
		},
		{
			name: "len(name < 4, len(cvv) < 3, number is not credit card, exp is not date",
			body: `
			{
				"name":"123",
				"cvv":"12",
				"number":"some",
				"exp":"abc",
				"secretKey":" ",
				"meta":{}
			}`,
			status: http.StatusUnprocessableEntity,
			errs: []string{
				"Field validation for 'Name' failed on the 'min' tag",
				"Field validation for 'CVV' failed on the 'min' tag",
				"Field validation for 'Number' failed on the 'credit_card' tag",
				"Field validation for 'Exp' failed on the 'datetime' tag",
			},
		},
		{
			name: "len(name) > 32, len(cvv) > 4, exp mismatch layout",
			body: fmt.Sprintf(`
			{
				"name":"%s",
				"cvv":"12345",
				"exp":"08/12/2025 12:00:00",
				"secretKey":" ",
				"number":"4111111111111111",
				"meta":{}
			}`, strings.Repeat("a", 33)),
			status: http.StatusUnprocessableEntity,
			errs: []string{
				"Field validation for 'Name' failed on the 'max' tag",
				"Field validation for 'CVV' failed on the 'max' tag",
				"Field validation for 'Exp' failed on the 'datetime' tag",
			},
		},
		{
			name: "cvv is not numeric",
			body: `
			{
				"cvv":"12a",
				"secretKey":" ",
				"name":"test",
				"number":"4111111111111111",
				"exp":"08/12/2025",
				"meta":{}
			}`,
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
				Post("/secrets/card").
				Body(tt.body).
				Expect(t).
				Status(tt.status).
				End()

			if len(tt.errs) > 0 {
				var response response.Response[any]
				result.JSON(&response)

				require.False(t, response.Success)
				require.Nil(t, response.Result)
				assert.ElementsMatch(t, tt.errs, response.Errors)
			}
		})
	}
}

func TestAddText_Fails_Validate(t *testing.T) {
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
				"Field validation for 'SecretKey' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Content' failed on the 'required' tag",
				"Field validation for 'Meta' failed on the 'required' tag",
			},
		},
		{
			name: "empty fields",
			body: `
			{
				"secretKey":"",
				"name":"",
				"content":"",
				"meta":{}
			}`,
			status: http.StatusUnprocessableEntity,
			errs: []string{
				"Field validation for 'SecretKey' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Content' failed on the 'required' tag",
			},
		},
		{
			name: "len(name) < 4",
			body: `
			{
				"name":"123",
				"secretKey":" ",
				"content":" ",
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
				"secretKey":" ",
				"content":" ",
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
				Post("/secrets/text").
				Body(tt.body).
				Expect(t).
				Status(tt.status).
				End()

			if len(tt.errs) > 0 {
				var response response.Response[any]
				result.JSON(&response)

				require.False(t, response.Success)
				require.Nil(t, response.Result)
				assert.ElementsMatch(t, tt.errs, response.Errors)
			}
		})
	}
}

func TestAddFile_Fails_Validate(t *testing.T) {
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
				"Field validation for 'SecretKey' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Filename' failed on the 'required' tag",
				"Field validation for 'Content' failed on the 'required' tag",
				"Field validation for 'Meta' failed on the 'required' tag",
			},
		},
		{
			name: "empty fields",
			body: `
			{
				"secretKey":"",
				"name":"",
				"filename":"",
				"content":"",
				"meta":{}
			}`,
			status: http.StatusUnprocessableEntity,
			errs: []string{
				"Field validation for 'SecretKey' failed on the 'required' tag",
				"Field validation for 'Name' failed on the 'required' tag",
				"Field validation for 'Filename' failed on the 'required' tag",
				"Field validation for 'Content' failed on the 'required' tag",
			},
		},
		{
			name: "len(name) < 4, content is not hexadecimal",
			body: `
			{
				"name":"123",
				"secretKey":" ",
				"filename":" ",
				"content":" ",
				"meta":{}
			}`,
			status: http.StatusUnprocessableEntity,
			errs: []string{
				"Field validation for 'Name' failed on the 'min' tag",
				"Field validation for 'Content' failed on the 'hexadecimal' tag",
			},
		},
		{
			name: "len(name) > 32",
			body: fmt.Sprintf(`
			{
				"name":"%s",
				"secretKey":" ",
				"filename":" ",
				"content":"74657374",
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
				Post("/secrets/file").
				Body(tt.body).
				Expect(t).
				Status(tt.status).
				End()

			if len(tt.errs) > 0 {
				var response response.Response[any]
				result.JSON(&response)

				require.False(t, response.Success)
				require.Nil(t, response.Result)
				assert.ElementsMatch(t, tt.errs, response.Errors)
			}
		})
	}
}
