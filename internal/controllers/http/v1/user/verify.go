package user

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/novoseltcev/passkeeper/internal/auth"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/common/response"
	domain "github.com/novoseltcev/passkeeper/internal/domains/user"
)

func Verify(service domain.Service) gin.HandlerFunc {
	type reqBody struct {
		Passphrase string `binding:"required"`
	}

	return func(c *gin.Context) {
		ownerID := auth.GetUserID(c)

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

		err := service.VerifyPassphrase(c, ownerID, body.Passphrase)
		if err != nil {
			if errors.Is(err, domain.ErrInvalidPassphrase) {
				c.AbortWithStatus(http.StatusConflict)
			} else {
				c.AbortWithStatus(http.StatusInternalServerError)
			}

			return
		}

		c.Status(http.StatusNoContent)
	}
}
