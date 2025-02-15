package response

type createdData[T string | int64] struct {
	ID T `json:"id"`
}

func NewCreate[T string | int64](id T) *Response[createdData[T]] {
	return NewSuccess(&createdData[T]{ID: id})
}
