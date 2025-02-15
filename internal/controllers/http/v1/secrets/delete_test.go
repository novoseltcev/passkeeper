package secrets_test

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steinfletcher/apitest"
	"go.uber.org/mock/gomock"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/secrets"
	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/domains/secrets/mocks"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
)

func TestDelete_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	root := gin.Default()
	service := mocks.NewMockService(ctrl)
	secrets.AddRoutes(&root.RouterGroup, service, guardMock)

	service.EXPECT().
		Delete(gomock.Any(), testID, testOwnerID).
		Return(nil)

	apitest.Handler(root.Handler()).
		Debug().
		Deletef("/secrets/%s", testID).
		Expect(t).
		Status(http.StatusNoContent).
		End()
}

func TestDelete_Fails(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	tests := []struct {
		name   string
		err    error
		status int
	}{
		{
			name:   "not found",
			err:    domain.ErrSecretNotFound,
			status: http.StatusNoContent,
		},
		{
			name:   "not my secret",
			err:    domain.ErrAnotherOwner,
			status: http.StatusForbidden,
		},
		{
			name:   "other",
			err:    testutils.Err,
			status: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := gin.Default()
			service := mocks.NewMockService(ctrl)
			secrets.AddRoutes(&root.RouterGroup, service, guardMock)

			service.EXPECT().
				Delete(gomock.Any(), testID, testOwnerID).
				Return(tt.err)

			apitest.New(tt.name).
				Handler(root.Handler()).
				Debug().
				Deletef("/secrets/%s", testID).
				Expect(t).
				Status(tt.status).
				End()
		})
	}
}
