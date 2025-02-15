package response

import (
	"fmt"

	"github.com/go-playground/validator/v10"
)

func NewValidationError(err validator.ValidationErrors) *Response[any] {
	response := &Response[any]{
		Success: false,
		Errors:  make([]string, 0),
	}

	for _, fe := range err {
		response.Errors = append(
			response.Errors,
			fmt.Sprintf("Field validation for '%s' failed on the '%s' tag", fe.Field(), fe.Tag()),
		)
	}

	return response
}
