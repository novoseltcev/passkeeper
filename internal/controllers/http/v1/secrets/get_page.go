package secrets

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/common/response"
	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/server/auth"
)

func GetPage(service domain.Service) func(c *gin.Context) {
	return func(c *gin.Context) {
		ownerID := auth.GetUserID(c)

		var req PaginationRequest
		if err := c.ShouldBindQuery(&req); err != nil {
			var vErr validator.ValidationErrors
			if errors.As(err, &vErr) {
				c.JSON(http.StatusUnprocessableEntity, response.NewValidationError(vErr))
			} else {
				c.JSON(http.StatusBadRequest, response.NewError(err))
			}

			return
		}

		page, err := service.GetPage(c, ownerID, req.Page, req.Limit)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)

			return
		}

		schemas := make([]SecretSchema, len(page.Items))
		for i, secret := range page.Items {
			schemas[i] = SecretSchema{
				ID:   string(secret.ID),
				Name: secret.Name,
				Type: secret.Type.String(),
			}
		}

		c.JSON(http.StatusOK, response.NewPaginated(schemas, req.Page, req.Limit, page.Pages))
	}
}

type PaginationRequest struct {
	Page  uint64 `binding:"required,gte=1"         form:"page"`
	Limit uint64 `binding:"required,gte=1,lte=100" form:"limit"`
}

type SecretSchema struct {
	ID   string `binding:"required"                               json:"id"`
	Name string `binding:"required"                               json:"name"`
	Type string `binding:"required,oneof=password card text file" json:"type"`
}
