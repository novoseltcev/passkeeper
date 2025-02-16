package secrets

import (
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/novoseltcev/passkeeper/internal/app/auth"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/common/response"
	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/models"
)

func GetByID(service domain.Service) func(c *gin.Context) {
	return func(c *gin.Context) {
		ownerID := auth.GetUserID(c)
		id := models.SecretID(c.Param("id"))

		secret, err := service.Get(c, id, ownerID)
		if err != nil {
			if errors.Is(err, domain.ErrSecretNotFound) {
				c.AbortWithStatus(http.StatusNotFound)
			} else if errors.Is(err, domain.ErrAnotherOwner) {
				c.AbortWithStatus(http.StatusForbidden)
			} else {
				c.AbortWithError(http.StatusInternalServerError, err)
			}

			return
		}

		c.JSON(http.StatusOK, response.NewSuccess(&responseSecret{
			ID:   string(secret.ID),
			Name: secret.Name,
			Type: secret.Type.String(),
			Data: hex.EncodeToString(secret.Data),
		}))
	}
}

type responseSecret struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `binding:"oneof=password card text file" json:"type"`
	Data string `binding:"hexadecimal"                   json:"data"`
}
