package auth

import (
	"context"

	"github.com/rivo/tview"

	"github.com/novoseltcev/passkeeper/internal/adapters"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/user"
	"github.com/novoseltcev/passkeeper/internal/tui/utils"
)

func NewPassphraseForm(pages *tview.Pages, state map[string]string, api adapters.API) *tview.Form {
	data := new(user.VerifyData)
	form := tview.NewForm().
		AddInputField("Passphrase", "", 0, nil, func(text string) { data.Passphrase = text }).
		AddButton("Verify", func() {
			if err := api.Verify(context.TODO(), state["token"], data); err != nil {
				panic(err) // TODO@novoseltcev: handle error
			}

			state["passphrase"] = data.Passphrase
			pages.SwitchToPage(utils.PageList)
		}).
		SetCancelFunc(func() { pages.SwitchToPage(utils.PageSignIn) })

	form.SetBorder(true).SetTitle("Enter passphrase")

	return form
}
