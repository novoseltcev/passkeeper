package auth

import (
	"context"

	"github.com/rivo/tview"

	"github.com/novoseltcev/passkeeper/internal/adapters"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/user"
	"github.com/novoseltcev/passkeeper/internal/tui/utils"
)

func NewSignUpForm(pages *tview.Pages, state map[string]string, api adapters.API) *tview.Form { // nolint: funlen
	data := new(user.RegisterData)
	confirmedPassword := ""

	validate := func() bool {
		return data.Login != "" &&
			data.Password != "" &&
			confirmedPassword != "" &&
			data.Passphrase != "" &&
			data.Password == confirmedPassword
	}

	form := tview.NewForm().
		AddInputField("Email", "", 0, nil, nil).
		AddPasswordField("Password", "", 0, '*', nil).
		AddPasswordField("Confirm password", "", 0, '*', nil).
		AddInputField("Passphrase", "", 0, nil, nil).
		AddButton("Sign Up", nil).
		AddButton("Back", func() {
			pages.SwitchToPage(utils.PageSignIn)
		})

	form.SetBorder(true).SetTitle("Sign Up")
	form.SetCancelFunc(func() {
		pages.SwitchToPage(utils.PageSignIn)
	})

	emailFld := utils.Must[*tview.InputField](form.GetFormItem(0))
	passwordFld := utils.Must[*tview.InputField](form.GetFormItem(1))
	confirmedPasswordFld := utils.Must[*tview.InputField](form.GetFormItem(2)) // nolint: mnd
	passphraseFld := utils.Must[*tview.InputField](form.GetFormItem(3))        // nolint: mnd
	btn := form.GetButton(0)
	btn.SetDisabled(true)
	btn.SetSelectedFunc(func() {
		token, err := api.Register(context.TODO(), data)
		if err != nil {
			emailFld.SetText(err.Error())

			return
		}

		state[utils.StateToken] = token
		state[utils.StatePassphrase] = data.Passphrase

		pages.SwitchToPage(utils.PageList)
	})

	emailFld.SetChangedFunc(func(text string) {
		data.Login = text

		btn.SetDisabled(!validate())
	})
	passwordFld.SetChangedFunc(func(text string) {
		data.Password = text

		btn.SetDisabled(!validate())
	})
	confirmedPasswordFld.SetChangedFunc(func(text string) {
		confirmedPassword = text

		btn.SetDisabled(!validate())
	})
	passphraseFld.SetChangedFunc(func(text string) {
		data.Passphrase = text

		btn.SetDisabled(!validate())
	})

	return form
}
