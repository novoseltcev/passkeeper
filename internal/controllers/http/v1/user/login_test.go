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
	"github.com/novoseltcev/passkeeper/internal/models"
	jwtmocks "github.com/novoseltcev/passkeeper/pkg/jwtmanager/mocks"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
)

const (
	testID       = models.UserID("test-id")
	testToken    = "test-token"
	testLogin    = "test@test.com"
	testPassword = "p@ssw0rd"
)

func TestLogin_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	root := gin.Default()
	service := domainmocks.NewMockService(ctrl)
	jwt := jwtmocks.NewMockManager(ctrl)
	user.AddRoutes(&root.RouterGroup, service, jwt, nil)

	service.EXPECT().
		Login(gomock.Any(), testLogin, testPassword).
		Return(testID, nil)

	jwt.EXPECT().
		GenerateToken(gomock.Any(), string(testID)).
		Return(testToken, nil)

	apitest.Handler(root.Handler()).
		Debug().
		Post("/user/login").
		Bodyf(`
		{
			"login":"%s",
			"password":"%s"
		}`, testLogin, testPassword).
		Expect(t).
		Status(http.StatusOK).
		Bodyf(`
		{
		  "success":true,
		  "result":{
		  	"token":"%s"
		  }
		}`, testToken).
		End()
}

func TestLogin_Fails_Validate(t *testing.T) {
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
			errs: []string{
				"Field validation for 'Login' failed on the 'required' tag",
				"Field validation for 'Password' failed on the 'required' tag",
			},
		},
		{
			name: "empty fields",
			body: `
			{
				"login":"",
				"password":""
			}`,
			status: http.StatusUnprocessableEntity,
			errs: []string{
				"Field validation for 'Login' failed on the 'required' tag",
				"Field validation for 'Password' failed on the 'required' tag",
			},
		},
		{
			name: "login is not email",
			body: `
			{
				"login":" ",
				"password":" "
			}`,
			status: http.StatusUnprocessableEntity,
			errs:   []string{"Field validation for 'Login' failed on the 'email' tag"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := gin.Default()
			user.AddRoutes(&root.RouterGroup, nil, nil, nil)

			result := apitest.Handler(root.Handler()).
				Debug().
				Post("/user/login").
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

var defaultLoginBody = `{"login": "test@test.com", "password": "testPassword"}`

func TestLogin_Fails_Login(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	tests := []struct {
		name   string
		err    error
		status int
	}{
		{
			name:   "authentication failed",
			err:    domain.ErrAuthenticationFailed,
			status: http.StatusUnauthorized,
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
			user.AddRoutes(&root.RouterGroup, service, nil, nil)

			service.EXPECT().
				Login(gomock.Any(), gomock.Any(), gomock.Any()).
				Return("", tt.err)

			apitest.New(tt.name).
				Handler(root.Handler()).
				Debug().
				Post("/user/login").
				Body(defaultLoginBody).
				Expect(t).
				Status(tt.status).
				End()
		})
	}
}

func TestLogin_Fails_GenerateToken(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	root := gin.Default()
	service := domainmocks.NewMockService(ctrl)
	jwt := jwtmocks.NewMockManager(ctrl)
	user.AddRoutes(&root.RouterGroup, service, jwt, nil)

	service.EXPECT().
		Login(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(testID, nil)

	jwt.EXPECT().
		GenerateToken(gomock.Any(), gomock.Any()).
		Return("", testutils.Err)

	apitest.Handler(root.Handler()).
		Debug().
		Post("/user/login").
		Body(defaultLoginBody).
		Expect(t).
		Status(http.StatusInternalServerError).
		End()
}
