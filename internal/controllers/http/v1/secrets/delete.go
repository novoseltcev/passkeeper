package secrets

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/novoseltcev/passkeeper/internal/auth"
	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/models"
)

func Delete(service domain.Service) func(c *gin.Context) {
	return func(c *gin.Context) {
		ownerID := auth.GetUserID(c)
		id := models.SecretID(c.Param("id"))

		err := service.Delete(c, id, ownerID)
		if err != nil {
			if errors.Is(err, domain.ErrSecretNotFound) {
				c.Status(http.StatusNoContent)
			} else if errors.Is(err, domain.ErrAnotherOwner) {
				c.AbortWithStatus(http.StatusForbidden)
			} else {
				c.AbortWithError(http.StatusInternalServerError, err)
			}

			return
		}

		c.Status(http.StatusNoContent)
	}
}
