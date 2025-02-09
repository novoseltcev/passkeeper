package v1

import (
	"github.com/gin-gonic/gin"

	"github.com/novoseltcev/passkeeper/internal/middleware"
	"github.com/novoseltcev/passkeeper/internal/server/auth"
	"github.com/novoseltcev/passkeeper/pkg/jwtmanager"
)

func AddRoutes(
	rg *gin.RouterGroup,
	jwt jwtmanager.Manager,
) {
	middleware.JWT(jwt, auth.IdentityKey)
	// TODO(novoseltcev): Add routes
}
