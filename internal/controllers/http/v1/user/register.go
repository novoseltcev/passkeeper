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

type RegisterData struct {
	Login      string `binding:"required,email"`
	Password   string `binding:"required,min=8"`
	Passphrase string `binding:"required,min=8"`
}

func Register(service domain.Service, jwt jwtmanager.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body RegisterData
		if err := c.ShouldBindJSON(&body); err != nil {
			var vErr validator.ValidationErrors
			if errors.As(err, &vErr) {
				c.JSON(http.StatusUnprocessableEntity, response.NewValidationError(vErr))
			} else {
				c.JSON(http.StatusBadRequest, response.NewError(err))
			}

			return
		}

		id, err := service.Register(c, body.Login, body.Password, body.Passphrase)
		if err != nil {
			if errors.Is(err, domain.ErrLoginIsBusy) {
				c.AbortWithStatus(http.StatusConflict)
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

		c.JSON(http.StatusCreated, response.NewSuccess(&RegisterBody{Token: token}))
	}
}

type RegisterBody struct {
	Token string `json:"token"`
}
