package secrets

import (
	"github.com/gin-gonic/gin"

	"github.com/novoseltcev/passkeeper/internal/domains/secrets"
)

func AddRoutes(rg *gin.RouterGroup, service secrets.Service, guard gin.HandlerFunc) {
	secretGroup := rg.Group("/secrets", guard)
	{
		secretGroup.GET("", GetPage(service))
		secretGroup.POST("/:id/decrypt", DecryptByID(service))
		secretGroup.DELETE("/:id", Delete(service))

		secretGroup.POST("/password", AddPassword(service))
		secretGroup.POST("/card", AddCard(service))
		secretGroup.POST("/file", AddFile(service))
		secretGroup.POST("/text", AddText(service))

		secretGroup.PUT("/password/:id", UpdatePassword(service))
		secretGroup.PUT("/card/:id", UpdateCard(service))
		secretGroup.PUT("/file/:id", UpdateFile(service))
		secretGroup.PUT("/text/:id", UpdateText(service))
	}
}
