package common

type Response[T any] struct {
	Success bool     `json:"success"`
	Errors  []string `json:"errors,omitempty"`
	Result  *T       `json:"result"`
}

func NewSuccessResponse[T any](result *T) *Response[T] {
	return &Response[T]{
		Success: true,
		Result:  result,
	}
}

func NewErrorResponse(errors ...string) *Response[any] {
	return &Response[any]{
		Success: false,
		Errors:  errors,
	}
}

type pagination struct {
	Page  uint64 `json:"page"`
	Limit uint64 `json:"limit"`
	Pages uint64 `json:"pages"`
}

type PaginatedResponse[T []V, V any] struct {
	Success    bool       `json:"success"`
	Result     T          `json:"result"`
	Pagination pagination `json:"pagination"`
}

func NewPaginatedResponse[T []V, V any](result T, page, limit, pages uint64) *PaginatedResponse[T, V] {
	return &PaginatedResponse[T, V]{
		Success: true,
		Result:  result,
		Pagination: pagination{
			Page:  page,
			Limit: limit,
			Pages: pages,
		},
	}
}

type createResponse[T string | int64] struct {
	ID T `json:"id"`
}

func NewCreateResponse[T string | int64](id T) *Response[createResponse[T]] {
	return NewSuccessResponse(&createResponse[T]{ID: id})
}
