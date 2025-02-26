// nolint: mnd
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

	typeFld := utils.Must[*tview.DropDown](form.GetFormItem(1))

	typeFld.SetSelectedFunc(func(text string, index int) {
		switch text {
		case "password": // nolint: dupl
			data := &secrets.PasswordSecretData{Meta: make(map[string]any)}

			clearNewFields(form, 2)
			form.AddInputField("Login", "", 0, nil, func(text string) { data.Login = text })
			form.AddInputField("Password", "", 0, nil, func(text string) { data.Password = text })
			form.AddTextArea("Meta", "", 0, 0, 256, func(text string) { data.Meta["k"] = text }) // nolint: mnd
			form.AddButton("Add", func() {
				data.Name = name
				data.Passphrase = state[utils.StatePassphrase]

				_, err := api.Add(context.TODO(), state[utils.StateToken], data)
				if err != nil {
					panic(err) // TODO@novoseltcev: handle error
				}

				pages.SwitchToPage(utils.PageList)
				clearNewFields(form, 2)
			})
		case "card": // nolint: dupl
			data := &secrets.CardSecretData{Meta: make(map[string]any)}

			clearNewFields(form, 2)
			form.AddInputField("Number", "", 0, nil, func(text string) { data.Number = text })
			form.AddInputField("Holder", "", 0, nil, func(text string) { data.Holder = text })
			form.AddInputField("CVV", "", 0, nil, func(text string) { data.CVV = text })
			form.AddInputField("Expiration", "", 0, nil, func(text string) { data.Exp = text })
			form.AddTextArea("Meta", "", 0, 0, 256, func(text string) { data.Meta["k"] = text }) // nolint: mnd
			form.AddButton("Add", func() {
				data.Name = name
				data.Passphrase = state[utils.StatePassphrase]

				_, err := api.Add(context.TODO(), state[utils.StateToken], data)
				if err != nil {
					panic(err) // TODO@novoseltcev: handle error
				}

				pages.SwitchToPage(utils.PageList)
				clearNewFields(form, 2)
			})
		case "text":
			data := &secrets.TextSecretData{Meta: make(map[string]any)}

			clearNewFields(form, 2)
			form.AddInputField("Content", "", 0, nil, func(text string) { data.Content = text })
			form.AddTextArea("Meta", "", 0, 0, 256, func(text string) { data.Meta["k"] = text }) // nolint: mnd
			form.AddButton("Add", func() {
				data.Name = name
				data.Passphrase = state[utils.StatePassphrase]

				_, err := api.Add(context.TODO(), state[utils.StateToken], data)
				if err != nil {
					panic(err) // TODO@novoseltcev: handle error
				}

				pages.SwitchToPage(utils.PageList)
				clearNewFields(form, 2)
			})
		case "file": // nolint: dupl
			data := &secrets.FileSecretData{Meta: make(map[string]any)}

			clearNewFields(form, 2)
			form.AddInputField("Filename", "", 0, nil, func(text string) { data.Filename = text })
			form.AddInputField("Content", "", 0, nil, func(text string) { data.Content = text })
			form.AddTextArea("Meta", "", 0, 0, 256, func(text string) { data.Meta["k"] = text }) // nolint: mnd
			form.AddButton("Add", func() {
				data.Name = name
				data.Passphrase = state[utils.StatePassphrase]

				_, err := api.Add(context.TODO(), state[utils.StateToken], data)
				if err != nil {
					panic(err) // TODO@novoseltcev: handle error
				}

				pages.SwitchToPage(utils.PageList)
				clearNewFields(form, 2)
			})
		}
	})

	return form
}

func clearNewFields(form *tview.Form, index int) {
	for range form.GetFormItemCount() - index {
		form.RemoveFormItem(index) // nolint: mnd
	}

	form.ClearButtons()
}
