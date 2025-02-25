// nolint: forcetypeassert
package secrets

import (
	"context"
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/novoseltcev/passkeeper/internal/adapters"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/secrets"
	"github.com/novoseltcev/passkeeper/internal/tui/utils"
)

// Not working form (need to fix focus).
func NewCardView(pages *tview.Pages, state map[string]string, api adapters.API) *tview.Form { // nolint: funlen
	form := tview.NewForm().AddInputField("Name", "", 0, nil, nil)
	nameFld := utils.Must[*tview.InputField](form.GetFormItem(0))

	init := false

	form.SetBorder(true).
		SetTitle("Loading... (press Esc to cancel)").
		SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
			if event.Key() == tcell.KeyEscape {
				init = false

				delete(state, "uuid")
				pages.SwitchToPage(utils.PageList)
				clearNewFields(form, 1)
				form.SetTitle("Loading... (press Esc to cancel)")
			}

			return event
		})

	form.SetFocusFunc(func() {
		if init {
			return
		}

		uuid, ok := state["uuid"]
		if !ok {
			panic("uuid shold be set in state")
		}

		secret, err := api.DecryptSecret(
			context.TODO(),
			state["token"],
			uuid,
			&secrets.DecryptByIDData{Passphrase: state["passphrase"]},
		)
		if err != nil {
			panic(err) // TODO@novoseltcev: handle error
		}

		form.SetTitle(fmt.Sprintf("Card <%s> - %s", secret.Type, uuid))

		switch secret.Type {
		case "password": // nolint: dupl
			data := &secrets.PasswordSecretData{
				Passphrase: state["passphrase"],
				Name:       secret.Name,
				Login:      secret.Data["login"].(string),
				Password:   secret.Data["password"].(string),
				Meta:       secret.Data["meta"].(map[string]any),
			}

			nameFld.SetText(secret.Name).SetChangedFunc(func(text string) { data.Name = text })
			form.AddInputField("Login", data.Login, 0, nil, func(text string) { data.Login = text }).
				AddInputField("Password", data.Name, 0, nil, func(text string) { data.Password = text }).
				AddTextArea("Meta", fmt.Sprint(data.Meta), 0, 0, 256, func(text string) {}). // nolint: mnd
				AddButton("Save", func() {
					if err := api.Update(context.TODO(), state["token"], secret.ID, data); err != nil {
						panic(err) // TODO@novoseltcev: handle error
					}
				})
		case "card":
			data := &secrets.CardSecretData{
				Passphrase: state["passphrase"],
				Name:       secret.Name,
				Number:     secret.Data["number"].(string),
				Holder:     secret.Data["holder"].(string),
				CVV:        secret.Data["cvv"].(string),
				Exp:        secret.Data["exp"].(string),
				Meta:       secret.Data["meta"].(map[string]any),
			}

			nameFld.SetText(secret.Name).SetChangedFunc(func(text string) { data.Name = text })
			form.AddInputField("Number", data.Number, 0, nil, func(text string) { data.Number = text }).
				AddInputField("Holder", data.Holder, 0, nil, func(text string) { data.Holder = text }).
				AddInputField("CVV", data.CVV, 0, nil, func(text string) { data.CVV = text }).
				AddInputField("Exp", data.Exp, 0, nil, func(text string) { data.Exp = text }).
				AddTextArea("Meta", fmt.Sprint(data.Meta), 0, 0, 256, func(text string) {}). // nolint: mnd
				AddButton("Save", func() {
					if err := api.Update(context.TODO(), state["token"], secret.ID, data); err != nil {
						panic(err) // TODO@novoseltcev: handle error
					}
				})
		case "text":
			data := &secrets.TextSecretData{
				Passphrase: state["passphrase"],
				Name:       secret.Name,
				Content:    secret.Data["content"].(string),
				Meta:       secret.Data["meta"].(map[string]any),
			}

			nameFld.SetText(secret.Name).SetChangedFunc(func(text string) { data.Name = text })
			form.AddInputField("Content", data.Content, 0, nil, func(text string) { data.Content = text }).
				AddTextArea("Meta", fmt.Sprint(data.Meta), 0, 0, 256, func(text string) {}). // nolint: mnd
				AddButton("Save", func() {
					if err := api.Update(context.TODO(), state["token"], secret.ID, data); err != nil {
						panic(err) // TODO@novoseltcev: handle error
					}
				})
		case "file": // nolint: dupl
			data := &secrets.FileSecretData{
				Passphrase: state["passphrase"],
				Name:       secret.Name,
				Filename:   secret.Data["filename"].(string),
				Content:    secret.Data["content"].(string),
				Meta:       secret.Data["meta"].(map[string]any),
			}

			nameFld.SetText(secret.Name).SetChangedFunc(func(text string) { data.Name = text })
			form.AddInputField("Filename", data.Filename, 0, nil, func(text string) { data.Filename = text }).
				AddInputField("Content", data.Content, 0, nil, func(text string) { data.Content = text }).
				AddTextArea("Meta", fmt.Sprint(data.Meta), 0, 0, 256, func(text string) {}). // nolint: mnd
				AddButton("Save", func() {
					if err := api.Update(context.TODO(), state["token"], secret.ID, data); err != nil {
						panic(err) // TODO@novoseltcev: handle error
					}
				})
		}
	})

	return form
}
