package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/novoseltcev/passkeeper/pkg/jwtmanager"
)

var (
	ErrNo      = errors.New("no token")
	ErrInvalid = errors.New("invalid token")
)

func JWT(mngr jwtmanager.Manager, identityKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := lookupToken(c)
		if err != nil {
			c.AbortWithError(http.StatusUnauthorized, err)

			return
		}

		token, err := mngr.ParseToken(c, tokenString)

		var pErr *jwtmanager.ParseError
		if err != nil {
			if errors.As(err, &pErr) {
				c.AbortWithError(http.StatusUnauthorized, err)
			} else {
				c.AbortWithError(http.StatusInternalServerError, err)
			}

			return
		}

		c.Set(identityKey, token.Subject)
		c.Next()
	}
}

func lookupToken(c *gin.Context) (string, error) {
	tokenString := strings.TrimSpace(c.GetHeader("Authorization"))
	if tokenString == "" {
		return "", ErrNo
	}

	if !strings.HasPrefix(tokenString, "Bearer ") {
		return "", ErrInvalid
	}

	return strings.TrimPrefix(tokenString, "Bearer "), nil
}
