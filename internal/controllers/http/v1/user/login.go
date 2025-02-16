package user

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/common/response"
	domain "github.com/novoseltcev/passkeeper/internal/domains/user"
	"github.com/novoseltcev/passkeeper/pkg/jwtmanager"
)

func Login(service domain.Service, jwt jwtmanager.Manager) gin.HandlerFunc {
	type reqBody struct {
		Login    string `binding:"required,email"`
		Password string `binding:"required"`
	}

	return func(c *gin.Context) {
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

		id, err := service.Login(c, body.Login, body.Password)
		if err != nil {
			if errors.Is(err, domain.ErrAuthenticationFailed) {
				c.AbortWithStatus(http.StatusUnauthorized)
			} else {
				c.AbortWithStatus(http.StatusInternalServerError)
			}

			return
		}

		token, err := jwt.GenerateToken(c, string(id))
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)

			return
		}

		c.JSON(http.StatusOK, response.NewSuccess(&responseData{
			Token: token,
		}))
	}
}

type responseData struct {
	Token string `json:"token"`
}
