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

func NewListView(pages *tview.Pages, state map[string]string, api adapters.API) *tview.List {
	list := tview.NewList().SetSelectedFocusOnly(true).SetWrapAround(false)
	list.SetBorder(true).SetTitle("Secrets")

	init := false

	list.SetFocusFunc(func() {
		if !init {
			if err := send(context.TODO(), list, pages, api, state, 0); err != nil {
				panic(err) // TODO@novoseltcev: handle error
			}

			init = true
		}
	}).SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == 's' {
			list.Clear()
			send(context.TODO(), list, pages, api, state, 0)
		} else if event.Rune() == 'a' {
			init = false

			list.Clear()
			pages.SwitchToPage(utils.PageAdd)
		} else if event.Rune() == 'd' {
			index := list.GetCurrentItem()
			_, uuid := list.GetItemText(index)

			if err := api.DeleteSecret(context.TODO(), state[utils.StateToken], uuid); err != nil {
				panic(err) // TODO@novoseltcev: handle error
			}

			list.RemoveItem(index)
		}

		return event
	})

	return list
}

func send(
	ctx context.Context,
	list *tview.List,
	pages *tview.Pages,
	api adapters.API,
	state map[string]string,
	offset uint64,
) error {
	items, total, err := api.GetSecretsPage(
		ctx,
		state[utils.StateToken],
		&secrets.PaginationRequest{Limit: 50, Offset: offset}, // nolint: mnd
	)
	if err != nil {
		return err
	}

	for _, item := range items {
		list.AddItem(
			item.Name+" <"+item.Type+">",
			item.ID,
			rune(list.GetItemCount()+1),
			func() {
				state[utils.StateID] = item.ID

				pages.SwitchToPage(utils.PageCard)
			},
		)
	}

	state[utils.StateTotal] = fmt.Sprint(total)
	state[utils.StateOffset] = fmt.Sprint(offset)

	return nil
}
