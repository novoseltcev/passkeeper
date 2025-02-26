// nolint: forcetypeassert
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/novoseltcev/passkeeper/internal/adapters"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/secrets"
	"github.com/novoseltcev/passkeeper/internal/tui/utils"
)

func NewCardView(pages *tview.Pages, state map[string]string, api adapters.API) *tview.Flex { // nolint: funlen
	var (
		cancel context.CancelFunc
		init   bool
		form   *tview.Form
	)

	view := tview.NewFlex().SetDirection(tview.FlexRow)
	view.SetBorder(true).SetTitle(("Card"))

	loader := tview.NewTextView()
	view.AddItem(loader, 1, 1, false)

	view.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			init = false

			cancel()
			delete(state, utils.StateID)
			pages.SwitchToPage(utils.PageList)
			loader.Clear()
			view.RemoveItem(form)
		}

		return event
	})

	view.SetFocusFunc(func() {
		if init {
			return
		}

		var ctx context.Context
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		id, token, passphrase := state[utils.StateID], state[utils.StateToken], state[utils.StatePassphrase]

		loader.SetText("Loading...")

		secret, err := api.DecryptSecret(
			ctx,
			state[utils.StateToken],
			id,
			&secrets.DecryptByIDData{Passphrase: state[utils.StatePassphrase]},
		)
		if err != nil {
			panic(err) // TODO@novoseltcev: handle error
		}

		init = true

		loader.Clear()
		view.SetTitle(fmt.Sprintf("Card <%s> - %s", secret.Type, id))

		switch secret.Type {
		case "password":
			form = NewUpdateForm(&secrets.PasswordSecretData{
				Passphrase: passphrase,
				Name:       secret.Name,
				Login:      secret.Data["login"].(string),
				Password:   secret.Data["password"].(string),
				Meta:       secret.Data["meta"].(map[string]any),
			}, id, token, passphrase, api)
		case "card":
			form = NewUpdateForm(&secrets.CardSecretData{
				Passphrase: passphrase,
				Name:       secret.Name,
				Number:     secret.Data["number"].(string),
				Holder:     secret.Data["holder"].(string),
				CVV:        secret.Data["cvv"].(string),
				Exp:        secret.Data["exp"].(string),
				Meta:       secret.Data["meta"].(map[string]any),
			}, id, token, passphrase, api)
		case "text":
			form = NewUpdateForm(&secrets.TextSecretData{
				Passphrase: passphrase,
				Name:       secret.Name,
				Content:    secret.Data["content"].(string),
				Meta:       secret.Data["meta"].(map[string]any),
			}, id, token, passphrase, api)
		case "file":
			form = NewUpdateForm(&secrets.FileSecretData{
				Passphrase: passphrase,
				Name:       secret.Name,
				Filename:   secret.Data["filename"].(string),
				Content:    secret.Data["content"].(string),
				Meta:       secret.Data["meta"].(map[string]any),
			}, id, token, passphrase, api)
		}

		view.AddItem(form, 0, 10, false) // nolint: mnd
	})

	return view
}

func NewUpdateForm[ // nolint: funlen
	T secrets.PasswordSecretData |
		secrets.CardSecretData |
		secrets.TextSecretData |
		secrets.FileSecretData](
	data *T,
	id, token, passphrase string,
	api adapters.API,
) *tview.Form {
	form := tview.NewForm().AddButton("Save", func() {
		if err := api.Update(context.TODO(), token, id, data); err != nil {
			panic(err) // TODO@novoseltcev: handle error
		}
	})

	btn := form.GetButton(0)
	btn.SetDisabled(true)

	switch data := any(data).(type) {
	case *secrets.PasswordSecretData:
		meta, err := json.Marshal(data.Meta)
		if err != nil {
			panic(err) // TODO@novoseltcev: handle error
		}

		return form.
			AddInputField("Name", data.Name, 0, nil, func(text string) {
				data.Name = text
				btn.SetDisabled(false)
			}).
			AddInputField("Login", data.Login, 0, nil, func(text string) {
				data.Login = text
				btn.SetDisabled(true)
			}).
			AddInputField("Password", data.Password, 0, nil, func(text string) {
				data.Password = text
				btn.SetDisabled(false)
			}).
			AddTextArea("Meta", string(meta), 0, 0, 256, func(text string) { // nolint: mnd
				btn.SetDisabled(false)
				json.Unmarshal([]byte(text), &data.Meta)
			})
	case *secrets.CardSecretData:
		meta, err := json.Marshal(data.Meta)
		if err != nil {
			panic(err) // TODO@novoseltcev: handle error
		}

		return form.
			AddInputField("Name", data.Name, 0, nil, func(text string) {
				data.Name = text
				btn.SetDisabled(false)
			}).
			AddInputField("Number", data.Number, 0, nil, func(text string) {
				data.Number = text
				btn.SetDisabled(false)
			}).
			AddInputField("Holder", data.Holder, 0, nil, func(text string) {
				data.Holder = text
				btn.SetDisabled(false)
			}).
			AddInputField("CVV", data.CVV, 0, nil, func(text string) {
				data.CVV = text
				btn.SetDisabled(false)
			}).
			AddInputField("Exp", data.Exp, 0, nil, func(text string) {
				data.Exp = text
				btn.SetDisabled(false)
			}).
			AddTextArea("Meta", string(meta), 0, 0, 256, func(text string) { // nolint: mnd
				btn.SetDisabled(false)
				json.Unmarshal([]byte(text), &data.Meta)
			})
	case *secrets.TextSecretData:
		meta, err := json.Marshal(data.Meta)
		if err != nil {
			panic(err) // TODO@novoseltcev: handle error
		}

		return form.
			AddInputField("Name", data.Name, 0, nil, func(text string) {
				data.Name = text
				btn.SetDisabled(false)
			}).
			AddInputField("Content", data.Content, 0, nil, func(text string) {
				data.Content = text
				btn.SetDisabled(false)
			}).
			AddTextArea("Meta", string(meta), 0, 0, 256, func(text string) { // nolint: mnd
				btn.SetDisabled(false)
				json.Unmarshal([]byte(text), &data.Meta)
			})
	case *secrets.FileSecretData:
		meta, err := json.Marshal(data.Meta)
		if err != nil {
			panic(err) // TODO@novoseltcev: handle error
		}

		return form.
			AddInputField("Name", data.Name, 0, nil, func(text string) {
				data.Name = text
				btn.SetDisabled(false)
			}).
			AddInputField("Filename", data.Filename, 0, nil, func(text string) {
				data.Filename = text
				btn.SetDisabled(false)
			}).
			AddInputField("Content", data.Content, 0, nil, func(text string) {
				data.Content = text
				btn.SetDisabled(false)
			}).
			AddTextArea("Meta", string(meta), 0, 0, 256, func(text string) { // nolint: mnd
				btn.SetDisabled(false)
				json.Unmarshal([]byte(text), &data.Meta)
			})
	default:
		panic("unreachable")
	}
}
