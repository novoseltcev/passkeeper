package tui

import (
	"github.com/rivo/tview"

	"github.com/novoseltcev/passkeeper/internal/adapters"
	"github.com/novoseltcev/passkeeper/internal/tui/utils"
)

func NewLayout(api adapters.API) *tview.Pages {
	state := make(map[string]string)
	pages := tview.NewPages()

	isAuth := state["token"] != ""
	if isAuth {
		pages.SwitchToPage(utils.PageList)
	} else {
		pages.SwitchToPage(utils.PageSignIn)
	}

	return pages
}
