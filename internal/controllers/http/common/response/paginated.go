package response

type pagination struct {
	Page  uint64 `json:"page"`
	Limit uint64 `json:"limit"`
	Pages uint64 `json:"pages"`
}

type PaginatedResponse[T any] struct {
	Success    bool       `json:"success"`
	Result     []T        `json:"result"`
	Pagination pagination `json:"pagination"`
}

func NewPaginated[T any](result []T, page, limit, pages uint64) *PaginatedResponse[T] {
	return &PaginatedResponse[T]{
		Success: true,
		Result:  result,
		Pagination: pagination{
			Page:  page,
			Limit: limit,
			Pages: pages,
		},
	}
}
