package middleware_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steinfletcher/apitest"
	"go.uber.org/mock/gomock"

	"github.com/novoseltcev/passkeeper/internal/middleware"
	"github.com/novoseltcev/passkeeper/pkg/jwtmanager"
	"github.com/novoseltcev/passkeeper/pkg/jwtmanager/mocks"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
)

const (
	identityKey     = "TEST_USER_ID"
	testTokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjo5OTk5OTk5OTk5OSwiaXNzIjoidGVzdElzc3VlciIsImp0aSI6ImYyMTZiOTk3LTY3N2EtNDI0ZS1hNjNmLTJlODBjYTNiYTZiOSJ9.gMEGtr7XBQvqZlLOV83rl6s3qaP2oS8eKOJCmovJJRE" // nolint: lll
)

func TestJWT_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	mngr := mocks.NewMockManager(ctrl)

	r := gin.New()
	r.Use(middleware.JWT(mngr, identityKey))
	r.GET("/test", func(c *gin.Context) { c.Header("X-User-ID", c.GetString(identityKey)) })
	mngr.EXPECT().ParseToken(testTokenString).Return(&jwtmanager.Token{
		ID:        "123",
		Subject:   "test",
		ExpiresAt: time.Now().Add(time.Hour),
	}, nil)

	apitest.Handler(r.Handler()).
		Get("/test").
		Header("Authorization", "Bearer "+testTokenString).
		Expect(t).
		Status(http.StatusOK).
		Header("X-User-ID", "test").
		End()
}

func TestJWT_FailsLookup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
	}{
		{name: "no header", header: ""},
		{name: "wrong prefix", header: "Bearer123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := gin.New()
			r.Use(middleware.JWT(nil, identityKey))

			apitest.Handler(r.Handler()).
				Get("/test").
				Header("Authorization", tt.header).
				Expect(t).
				Status(http.StatusUnauthorized).
				End()
		})
	}
}

func TestJWT_FailsParseToken(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	mngr := mocks.NewMockManager(ctrl)

	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "parse error", err: jwtmanager.NewParseError("", 0), status: http.StatusUnauthorized},
		{name: "other error", err: testutils.Err, status: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := gin.New()
			r.Use(middleware.JWT(mngr, identityKey))
			mngr.EXPECT().ParseToken(testTokenString).Return(nil, tt.err)

			apitest.Handler(r.Handler()).
				Get("/test").
				Header("Authorization", "Bearer "+testTokenString).
				Expect(t).
				Status(tt.status).
				End()
		})
	}
}
