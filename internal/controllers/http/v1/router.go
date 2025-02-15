package v1

import (
	"github.com/gin-gonic/gin"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/secrets"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/user"
	secretsdomain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	userdomain "github.com/novoseltcev/passkeeper/internal/domains/user"
	"github.com/novoseltcev/passkeeper/pkg/jwtmanager"
)

func AddRoutes(
	rg *gin.RouterGroup,
	jwt jwtmanager.Manager,
	guard gin.HandlerFunc,
	secretService secretsdomain.Service,
	userService userdomain.Service,
) {
	secrets.AddRoutes(rg, secretService, guard)
	user.AddRoutes(rg, userService, jwt, guard)
}
