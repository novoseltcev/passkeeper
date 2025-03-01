package response

type CreatedData[T string | int64] struct {
	ID T `json:"id"`
}

func NewCreate[T string | int64](id T) *Response[CreatedData[T]] {
	return NewSuccess(&CreatedData[T]{ID: id})
}
