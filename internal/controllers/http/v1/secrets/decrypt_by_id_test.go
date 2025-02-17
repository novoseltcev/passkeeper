package secrets_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steinfletcher/apitest"
	"go.uber.org/mock/gomock"

	"github.com/novoseltcev/passkeeper/internal/app/auth"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/secrets"
	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/domains/secrets/mocks"
	"github.com/novoseltcev/passkeeper/internal/models"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
)

const (
	testOwnerID     = models.UserID("f535204f-9283-4c1a-8e68-8834c6ae83fb")
	testID          = models.SecretID("c4865c2f-8fa8-46a1-97b1-74242c68bbd0")
	testHex         = "74657374"
	testName        = "test"
	testDecodedData = `{"key":"value"}`
)

var testData = []byte(testName)

func guardMock(c *gin.Context) {
	c.Set(auth.IdentityKey, string(testOwnerID))
	c.Next()
}

func TestDecryptByID_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	root := gin.Default()
	service := mocks.NewMockService(ctrl)
	secrets.AddRoutes(&root.RouterGroup, service, guardMock)

	service.EXPECT().
		Get(gomock.Any(), testID, testOwnerID, testPassphrase).
		Return(&models.Secret{
			ID:   testID,
			Name: testName,
			Data: []byte(testDecodedData),
			Type: models.SecretTypeFile,
		}, nil)

	apitest.Handler(root.Handler()).
		Debug().
		Postf("/secrets/%s/decrypt", testID).
		Bodyf(`{"passphrase":"%s"}`, testPassphrase).
		Expect(t).
		Status(http.StatusOK).
		Bodyf(`
		{
		  "success":true,
		  "result":{
		 	"id":"%s",
		 	"name":"%s",
		 	"type":"file",
		 	"data":%s
		  }
		}`, testID, testName, testDecodedData).
		End()
}

func TestDecryptByID_Fails_Validate(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

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
			errs:   []string{"Field validation for 'Passphrase' failed on the 'required' tag"},
		},
		{
			name:   "empty field",
			body:   `{"passphrase":""}`,
			status: http.StatusUnprocessableEntity,
			errs:   []string{"Field validation for 'Passphrase' failed on the 'required' tag"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := gin.Default()
			secrets.AddRoutes(&root.RouterGroup, mocks.NewMockService(ctrl), guardMock)

			result := apitest.Handler(root.Handler()).
				Debug().
				Postf("/secrets/%s/decrypt", testID).
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

func TestGet_Fails_Get(t *testing.T) {
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
			name:   "invalid passphrase",
			err:    domain.ErrInvalidPassphrase,
			status: http.StatusConflict,
		},
		{
			name:   "other",
			err:    testutils.Err,
			status: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := gin.Default()
			service := mocks.NewMockService(ctrl)
			secrets.AddRoutes(&root.RouterGroup, service, guardMock)

			service.EXPECT().
				Get(gomock.Any(), testID, testOwnerID, testPassphrase).
				Return(nil, tt.err)

			apitest.New(tt.name).
				Handler(root.Handler()).
				Debug().
				Postf("/secrets/%s/decrypt", testID).
				Bodyf(`{"passphrase":"%s"}`, testPassphrase).
				Expect(t).
				Status(tt.status).
				End()
		})
	}
}
