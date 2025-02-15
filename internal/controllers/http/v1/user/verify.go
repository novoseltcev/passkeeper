package user

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/common/response"
	domain "github.com/novoseltcev/passkeeper/internal/domains/user"
	"github.com/novoseltcev/passkeeper/internal/server/auth"
)

func Verify(service domain.Service) gin.HandlerFunc {
	type reqBody struct {
		SecretKey string `binding:"required"`
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

		err := service.VerifySecret(c, ownerID, body.SecretKey)
		if err != nil {
			if errors.Is(err, domain.ErrInvalidSecretKey) {
				c.AbortWithStatus(http.StatusConflict)
			} else {
				c.AbortWithStatus(http.StatusInternalServerError)
			}

			return
		}

		c.Status(http.StatusNoContent)
	}
}
