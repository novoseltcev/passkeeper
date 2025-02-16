package secrets

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/novoseltcev/passkeeper/internal/app/auth"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/common/response"
	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/models"
)

func addSecret[T any](
	c *gin.Context,
	fn func(c *gin.Context, ownerID models.UserID, body *T) (models.SecretID, error),
) {
	ownerID := auth.GetUserID(c)

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

	id, err := fn(c, ownerID, &body)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidPassphrase) {
			c.AbortWithStatus(http.StatusConflict)
		} else {
			c.AbortWithError(http.StatusInternalServerError, err)
		}

		return
	}

	c.JSON(http.StatusCreated, response.NewCreate(string(id)))
}

func AddPassword(service domain.Service) func(c *gin.Context) {
	return func(c *gin.Context) {
		addSecret(c, func(c *gin.Context, ownerID models.UserID, body *PasswordSecretData) (models.SecretID, error) {
			return service.Create(c, ownerID, body.Passphrase, body.Name, &domain.PasswordData{
				Login:    body.Login,
				Password: body.Password,
				Meta:     body.Meta,
			})
		})
	}
}

func AddCard(service domain.Service) func(c *gin.Context) {
	return func(c *gin.Context) {
		addSecret(c, func(c *gin.Context, ownerID models.UserID, body *CardSecretData) (models.SecretID, error) {
			return service.Create(c, ownerID, body.Passphrase, body.Name, &domain.CardData{
				Number: body.Number,
				Holder: body.Holder,
				Exp:    body.Exp,
				CVV:    body.CVV,
				Meta:   body.Meta,
			})
		})
	}
}

func AddText(service domain.Service) func(c *gin.Context) {
	return func(c *gin.Context) {
		addSecret(c, func(c *gin.Context, ownerID models.UserID, body *TextSecretData) (models.SecretID, error) {
			return service.Create(c, ownerID, body.Passphrase, body.Name, &domain.TextData{
				Content: body.Content,
				Meta:    body.Meta,
			})
		})
	}
}

func AddFile(service domain.Service) func(c *gin.Context) {
	return func(c *gin.Context) {
		addSecret(c, func(c *gin.Context, ownerID models.UserID, body *FileSecretData) (models.SecretID, error) {
			return service.Create(c, ownerID, body.Passphrase, body.Name, &domain.FileData{
				Filename: body.Filename,
				Content:  body.Content,
				Meta:     body.Meta,
			})
		})
	}
}
