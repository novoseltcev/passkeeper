package srv_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steinfletcher/apitest"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/srv"
)

func TestPing(t *testing.T) {
	t.Parallel()

	r := gin.New()
	srv.AddRoutes(&r.RouterGroup)

	apitest.Handler(r.Handler()).
		Get("/ping").
		Expect(t).
		Status(http.StatusOK).
		Body(`{"message":"pong"}`).
		End()
}
