package secrets_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steinfletcher/apitest"
	"go.uber.org/mock/gomock"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/secrets"
	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/domains/secrets/mocks"
	"github.com/novoseltcev/passkeeper/internal/models"
	"github.com/novoseltcev/passkeeper/internal/server/auth"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
)

const (
	testOwnerID = models.UserID("f535204f-9283-4c1a-8e68-8834c6ae83fb")
	testID      = models.SecretID("c4865c2f-8fa8-46a1-97b1-74242c68bbd0")
	testHex     = "74657374"
	testName    = "test"
)

var testData = []byte(testName)

func guardMock(c *gin.Context) {
	c.Set(auth.IdentityKey, string(testOwnerID))
	c.Next()
}

func TestGetByID_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	root := gin.Default()
	service := mocks.NewMockService(ctrl)
	secrets.AddRoutes(&root.RouterGroup, service, guardMock)

	service.EXPECT().
		Get(gomock.Any(), testID, testOwnerID).
		Return(&models.Secret{
			ID:   testID,
			Name: testName,
			Data: testData,
			Type: models.SecretTypeFile,
		}, nil)

	apitest.Handler(root.Handler()).
		Debug().
		Getf("/secrets/%s", testID).
		Expect(t).
		Status(http.StatusOK).
		Bodyf(`
		{
		  "success":true,
		  "result":{
		 	"id":"%s",
		 	"name":"%s",
		 	"type":"file",
		 	"data":"%s"
		  }
		}`, testID, testName, testHex).
		End()
}

func TestGet_Fails(t *testing.T) {
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
				Get(gomock.Any(), testID, testOwnerID).
				Return(nil, tt.err)

			apitest.New(tt.name).
				Handler(root.Handler()).
				Debug().
				Getf("/secrets/%s", testID).
				Expect(t).
				Status(tt.status).
				End()
		})
	}
}
