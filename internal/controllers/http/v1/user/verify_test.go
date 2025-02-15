package user_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steinfletcher/apitest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/common/response"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/user"
	domain "github.com/novoseltcev/passkeeper/internal/domains/user"
	domainmocks "github.com/novoseltcev/passkeeper/internal/domains/user/mocks"
	"github.com/novoseltcev/passkeeper/internal/server/auth"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
)

func guardMock(c *gin.Context) {
	c.Set(auth.IdentityKey, string(testID))
	c.Next()
}

func TestVerify_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	root := gin.Default()
	service := domainmocks.NewMockService(ctrl)
	user.AddRoutes(&root.RouterGroup, service, nil, guardMock)

	service.EXPECT().
		VerifySecret(gomock.Any(), testID, testSecretKey).
		Return(nil)

	apitest.Handler(root.Handler()).
		Debug().
		Post("/user/verify-secret").
		Bodyf(`{"secretKey":"%s"}`, testSecretKey).
		Expect(t).
		Status(http.StatusNoContent).
		End()
}

func TestVerify_Fails_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		status int
		errs   []string
	}{
		{
			name:   "invalid body",
			body:   "",
			status: http.StatusBadRequest,
		},
		{
			name:   "empty body",
			body:   `{}`,
			status: http.StatusUnprocessableEntity,
			errs:   []string{"Field validation for 'SecretKey' failed on the 'required' tag"},
		},
		{
			name:   "empty fields",
			body:   `{"secretKey":""}`,
			status: http.StatusUnprocessableEntity,
			errs:   []string{"Field validation for 'SecretKey' failed on the 'required' tag"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := gin.Default()
			user.AddRoutes(&root.RouterGroup, nil, nil, guardMock)

			result := apitest.Handler(root.Handler()).
				Debug().
				Post("/user/verify-secret").
				Body(tt.body).
				Expect(t).
				Status(tt.status).
				End()

			if tt.status == http.StatusUnprocessableEntity {
				var body response.Response[any]
				result.JSON(&body)

				require.False(t, body.Success)
				require.Nil(t, body.Result)
				assert.ElementsMatch(t, body.Errors, tt.errs)
			}
		})
	}
}

func TestVerify_Fails_Verify(t *testing.T) {
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := gin.Default()
			service := domainmocks.NewMockService(ctrl)
			user.AddRoutes(&root.RouterGroup, service, nil, guardMock)

			service.EXPECT().
				VerifySecret(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(tt.err)

			apitest.New(tt.name).
				Handler(root.Handler()).
				Debug().
				Post("/user/verify-secret").
				Body(`{"secretKey": "testSecretKey"}`).
				Expect(t).
				Status(tt.status).
				End()
		})
	}
}
