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

func Register(service domain.Service, jwt jwtmanager.Manager) gin.HandlerFunc {
	type reqBody struct {
		Login     string `binding:"required,email"`
		Password  string `binding:"required,min=8"`
		SecretKey string `binding:"required,min=8"`
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

		id, err := service.Register(c, body.Login, body.Password, body.SecretKey)
		if err != nil {
			if errors.Is(err, domain.ErrLoginIsBusy) {
				c.AbortWithStatus(http.StatusConflict)
			} else {
				c.AbortWithStatus(http.StatusInternalServerError)
			}

			return
		}

		token, err := jwt.GenerateToken(string(id))
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)

			return
		}

		c.JSON(http.StatusCreated, response.NewSuccess(&responseData{
			Token: token,
		}))
	}
}
