package auth

import (
	"log"

	"github.com/gin-gonic/gin"

	"github.com/novoseltcev/passkeeper/internal/models"
)

const IdentityKey = "USER_ID"

func GetUserID(c *gin.Context) models.UserID {
	id := c.GetString(IdentityKey)
	if id == "" {
		log.Panic("endpoint unguarded, but require user id")
	}

	return models.UserID(id)
}
