package auth

import (
	"context"
	"errors"

	"github.com/rivo/tview"

	"github.com/novoseltcev/passkeeper/internal/adapters"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/user"
	"github.com/novoseltcev/passkeeper/internal/tui/utils"
)

func NewSignInForm(pages *tview.Pages, state map[string]string, api adapters.API) *tview.Form {
	data := new(user.LoginData)
	rememberMe := false

	form := tview.NewForm().
		AddInputField("Email", "", 0, nil, nil).
		AddPasswordField("Password", "", 0, '*', nil).
		AddCheckbox("Remember me", rememberMe, func(checked bool) { rememberMe = checked }).
		AddButton("Log In", nil).
		AddButton("Create account", func() {
			pages.SwitchToPage(utils.PageSignUp)
		})

	form.SetBorder(true).SetTitle("Sign In")

	emailFld := utils.Must[*tview.InputField](form.GetFormItem(0))
	passwordFld := utils.Must[*tview.InputField](form.GetFormItem(1))
	btn := form.GetButton(0)
	btn.SetDisabled(true)
	btn.SetSelectedFunc(func() {
		token, err := api.Login(context.TODO(), data)
		if errors.Is(err, adapters.ErrUnauthorized) {
			emailFld.SetText("Incorrect email or password")
			passwordFld.SetText("")

			return
		}

		if err != nil {
			emailFld.SetText(err.Error())

			return
		}

		state["token"] = token

		pages.SwitchToPage(utils.PagePassphrase)
	})

	emailFld.SetChangedFunc(func(text string) {
		data.Login = text
		btn.SetDisabled(data.Login == "" || data.Password == "")
	})
	passwordFld.SetChangedFunc(func(text string) {
		data.Password = text
		btn.SetDisabled(data.Login == "" || data.Password == "")
	})

	return form
}
