package user

import (
	"github.com/gin-gonic/gin"

	"github.com/novoseltcev/passkeeper/internal/domains/user"
	"github.com/novoseltcev/passkeeper/pkg/jwtmanager"
)

func AddRoutes(rg *gin.RouterGroup, service user.Service, jwt jwtmanager.Manager, guard gin.HandlerFunc) {
	userGroup := rg.Group("/user")
	{
		userGroup.POST("/login", Login(service, jwt))
		userGroup.POST("/register", Register(service, jwt))
		userGroup.POST("/verify-secret", guard, Verify(service))
	}
}
