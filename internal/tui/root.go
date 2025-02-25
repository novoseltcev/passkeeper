package tui

import (
	"github.com/rivo/tview"

	"github.com/novoseltcev/passkeeper/internal/adapters"
	"github.com/novoseltcev/passkeeper/internal/tui/auth"
	"github.com/novoseltcev/passkeeper/internal/tui/secrets"
	"github.com/novoseltcev/passkeeper/internal/tui/utils"
)

func NewLayout(api adapters.API) *tview.Pages {
	state := make(map[string]string)
	pages := tview.NewPages()
	pages.AddPage(utils.PageSignIn, auth.NewSignInForm(pages, state, api), true, false)
	pages.AddPage(utils.PageSignUp, auth.NewSignUpForm(pages, state, api), true, false)
	pages.AddPage(utils.PagePassphrase, auth.NewPassphraseForm(pages, state, api), true, false)
	pages.AddPage(utils.PageList, secrets.NewListView(pages, state, api), true, false)
	pages.AddPage(utils.PageCard, secrets.NewCardView(pages, state, api), true, false)
	pages.AddPage(utils.PageAdd, secrets.NewAddView(pages, state, api), true, false)

	isAuth := state["token"] != ""
	if isAuth {
		pages.SwitchToPage(utils.PageList)
	} else {
		pages.SwitchToPage(utils.PageSignIn)
	}

	return pages
}
