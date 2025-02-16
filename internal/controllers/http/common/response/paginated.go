package response

type pagination struct {
	Limit  uint64 `json:"limit"`
	Offset uint64 `json:"offset"`
	Total  uint64 `json:"total"`
}

type PaginatedResponse[T any] struct {
	Success    bool       `json:"success"`
	Result     []T        `json:"result"`
	Pagination pagination `json:"pagination"`
}

func NewPaginated[T any](result []T, limit, offset, total uint64) *PaginatedResponse[T] {
	return &PaginatedResponse[T]{
		Success: true,
		Result:  result,
		Pagination: pagination{
			Offset: offset,
			Limit:  limit,
			Total:  total,
		},
	}
}
