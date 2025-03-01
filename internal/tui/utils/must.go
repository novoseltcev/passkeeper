package utils

import (
	"reflect"

	"github.com/rivo/tview"
)

func Must[T tview.Primitive](p tview.Primitive) T {
	r, ok := p.(T)
	if !ok {
		panic("Must: not a " + reflect.TypeOf(p).String())
	}

	return r
}
