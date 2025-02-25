package secrets

import (
	"context"

	"github.com/rivo/tview"

	"github.com/novoseltcev/passkeeper/internal/adapters"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/secrets"
	"github.com/novoseltcev/passkeeper/internal/tui/utils"
)

func NewAddView(pages *tview.Pages, state map[string]string, api adapters.API) *tview.Form { // nolint: funlen
	name := ""
	form := tview.NewForm().
		AddInputField("Name", "", 0, nil, func(text string) { name = text }).
		AddDropDown("Type", []string{"password", "card", "text", "file"}, 0, nil).
		SetCancelFunc(func() {
			pages.SwitchToPage(utils.PageList)
		})

	form.SetBorder(true).SetTitle("Add secret")

	// nameFld := utils.Must[*tview.InputField](form.GetFormItem(0))
	typeFld := utils.Must[*tview.DropDown](form.GetFormItem(1))

	typeFld.SetSelectedFunc(func(text string, index int) {
		switch text {
		case "password":
			data := &secrets.PasswordSecretData{Meta: make(map[string]any)}

			clearNewFields(form)
			form.AddInputField("Login", "", 0, nil, func(text string) { data.Login = text })
			form.AddInputField("Password", "", 0, nil, func(text string) { data.Password = text })
			form.AddTextArea("Meta", "", 0, 0, 256, func(text string) { data.Meta["k"] = text }) // nolint: mnd
			form.AddButton("Add", func() {
				data.Name = name
				data.Passphrase = state["passphrase"]

				_, err := api.Add(context.TODO(), state["token"], data)
				if err != nil {
					panic(err) // TODO@novoseltcev: handle error
				}

				pages.SwitchToPage(utils.PageList)
				clearNewFields(form)
			})
		case "card":
			data := &secrets.CardSecretData{Meta: make(map[string]any)}

			clearNewFields(form)
			form.AddInputField("Number", "", 0, nil, func(text string) { data.Number = text })
			form.AddInputField("Holder", "", 0, nil, func(text string) { data.Holder = text })
			form.AddInputField("CVV", "", 0, nil, func(text string) { data.CVV = text })
			form.AddInputField("Expiration", "", 0, nil, func(text string) { data.Exp = text })
			form.AddTextArea("Meta", "", 0, 0, 256, func(text string) { data.Meta["k"] = text }) // nolint: mnd
			form.AddButton("Add", func() {
				data.Name = name
				data.Passphrase = state["passphrase"]

				_, err := api.Add(context.TODO(), state["token"], data)
				if err != nil {
					panic(err) // TODO@novoseltcev: handle error
				}

				pages.SwitchToPage(utils.PageList)
				clearNewFields(form)
			})
		case "text":
			data := &secrets.TextSecretData{Meta: make(map[string]any)}

			clearNewFields(form)
			form.AddInputField("Content", "", 0, nil, func(text string) { data.Content = text })
			form.AddTextArea("Meta", "", 0, 0, 256, func(text string) { data.Meta["k"] = text }) // nolint: mnd
			form.AddButton("Add", func() {
				data.Name = name
				data.Passphrase = state["passphrase"]

				_, err := api.Add(context.TODO(), state["token"], data)
				if err != nil {
					panic(err) // TODO@novoseltcev: handle error
				}

				pages.SwitchToPage(utils.PageList)
				clearNewFields(form)
			})
		case "file":
			data := &secrets.FileSecretData{Meta: make(map[string]any)}

			clearNewFields(form)
			form.AddInputField("Filename", "", 0, nil, func(text string) { data.Filename = text })
			form.AddInputField("Content", "", 0, nil, func(text string) { data.Content = text })
			form.AddTextArea("Meta", "", 0, 0, 256, func(text string) { data.Meta["k"] = text }) // nolint: mnd
			form.AddButton("Add", func() {
				data.Name = name
				data.Passphrase = state["passphrase"]

				_, err := api.Add(context.TODO(), state["token"], data)
				if err != nil {
					panic(err) // TODO@novoseltcev: handle error
				}

				pages.SwitchToPage(utils.PageList)
				clearNewFields(form)
			})
		}
	})

	return form
}

func clearNewFields(form *tview.Form) {
	for range form.GetFormItemCount() - 2 {
		form.RemoveFormItem(2) // nolint: mnd
	}

	form.ClearButtons()
}
