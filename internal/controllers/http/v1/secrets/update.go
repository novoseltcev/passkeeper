package secrets

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/novoseltcev/passkeeper/internal/auth"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/common/response"
	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/models"
)

func updateSecret[T any](
	c *gin.Context,
	fn func(c *gin.Context, id models.SecretID, ownerID models.UserID, body *T) error,
) {
	ownerID := auth.GetUserID(c)
	id := models.SecretID(c.Param("id"))

	var body T

	if err := c.ShouldBindJSON(&body); err != nil {
		var vErr validator.ValidationErrors
		if errors.As(err, &vErr) {
			c.JSON(http.StatusUnprocessableEntity, response.NewValidationError(vErr))
		} else {
			c.JSON(http.StatusBadRequest, response.NewError(err))
		}

		return
	}

	err := fn(c, id, ownerID, &body)
	if err != nil {
		if errors.Is(err, domain.ErrSecretNotFound) {
			c.Status(http.StatusNotFound)
		} else if errors.Is(err, domain.ErrAnotherOwner) {
			c.Status(http.StatusForbidden)
		} else if errors.Is(err, domain.ErrInvalidSecretType) {
			c.AbortWithStatus(http.StatusConflict)
		} else {
			c.AbortWithError(http.StatusInternalServerError, err)
		}

		return
	}

	c.Status(http.StatusNoContent)
}

func UpdatePassword(service domain.Service) func(c *gin.Context) {
	return func(c *gin.Context) {
		updateSecret(c, func(c *gin.Context, id models.SecretID, ownerID models.UserID, body *PasswordSecretData) error {
			return service.Update(c, id, ownerID, body.Passphrase, body.Name, &domain.PasswordData{
				Login:    body.Login,
				Password: body.Password,
				Meta:     body.Meta,
			})
		})
	}
}

func UpdateCard(service domain.Service) func(c *gin.Context) {
	return func(c *gin.Context) {
		updateSecret(c, func(c *gin.Context, id models.SecretID, ownerID models.UserID, body *CardSecretData) error {
			return service.Update(c, id, ownerID, body.Passphrase, body.Name, &domain.CardData{
				Number: body.Number,
				Holder: body.Holder,
				Exp:    body.Exp,
				CVV:    body.CVV,
				Meta:   body.Meta,
			})
		})
	}
}

func UpdateText(service domain.Service) func(c *gin.Context) {
	return func(c *gin.Context) {
		updateSecret(c, func(c *gin.Context, id models.SecretID, ownerID models.UserID, body *TextSecretData) error {
			return service.Update(c, id, ownerID, body.Passphrase, body.Name, &domain.TextData{
				Content: body.Content,
				Meta:    body.Meta,
			})
		})
	}
}

func UpdateFile(service domain.Service) func(c *gin.Context) {
	return func(c *gin.Context) {
		updateSecret(c, func(c *gin.Context, id models.SecretID, ownerID models.UserID, body *FileSecretData) error {
			return service.Update(c, id, ownerID, body.Passphrase, body.Name, &domain.FileData{
				Filename: body.Filename,
				Content:  body.Content,
				Meta:     body.Meta,
			})
		})
	}
}
