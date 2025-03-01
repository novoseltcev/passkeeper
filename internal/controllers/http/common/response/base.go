package response

type Response[T any] struct {
	Success bool     `json:"success"`
	Errors  []string `json:"errors,omitempty"`
	Result  *T       `json:"result"`
}

func NewSuccess[T any](result *T) *Response[T] {
	return &Response[T]{
		Success: true,
		Result:  result,
	}
}

func NewError(errs ...error) *Response[any] {
	response := &Response[any]{
		Success: false,
		Errors:  make([]string, 0, len(errs)),
	}

	for _, err := range errs {
		response.Errors = append(response.Errors, err.Error())
	}

	return response
}
