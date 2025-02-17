package secrets

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/novoseltcev/passkeeper/internal/app/auth"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/common/response"
	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/models"
)

func DecryptByID(service domain.Service) func(c *gin.Context) {
	type reqBody struct {
		Passphrase string `binding:"required"`
	}

	return func(c *gin.Context) {
		ownerID := auth.GetUserID(c)
		id := models.SecretID(c.Param("id"))

		var body reqBody
		if err := c.ShouldBindJSON(&body); err != nil {
			var vErr validator.ValidationErrors
			if errors.As(err, &vErr) {
				c.JSON(http.StatusUnprocessableEntity, response.NewValidationError(vErr))
			} else {
				c.JSON(http.StatusBadRequest, response.NewError(err))
			}

			return
		}

		secret, err := service.Get(c, id, ownerID, body.Passphrase)
		if err != nil {
			if errors.Is(err, domain.ErrSecretNotFound) {
				c.AbortWithStatus(http.StatusNotFound)
			} else if errors.Is(err, domain.ErrAnotherOwner) {
				c.AbortWithStatus(http.StatusForbidden)
			} else if errors.Is(err, domain.ErrInvalidPassphrase) {
				c.AbortWithStatus(http.StatusConflict)
			} else {
				c.AbortWithError(http.StatusInternalServerError, err)
			}

			return
		}

		var data map[string]any
		if err := json.Unmarshal(secret.Data, &data); err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)

			return
		}

		c.JSON(http.StatusOK, response.NewSuccess(&responseSecret{
			ID:   string(secret.ID),
			Name: secret.Name,
			Type: secret.Type.String(),
			Data: data,
		}))
	}
}

type responseSecret struct {
	ID   string         `json:"id"`
	Name string         `json:"name"`
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}
