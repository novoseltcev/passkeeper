package secrets_test

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/steinfletcher/apitest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/common/response"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/secrets"
	domain "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/domains/secrets/mocks"
	"github.com/novoseltcev/passkeeper/internal/models"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
)

func TestGetPage_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	root := gin.Default()
	service := mocks.NewMockService(ctrl)
	secrets.AddRoutes(&root.RouterGroup, service, guardMock)

	var limit, offset, total uint64 = 10, 0, 30

	service.EXPECT().
		GetPage(gomock.Any(), testOwnerID, limit, offset).
		Return(domain.NewPage([]models.Secret{
			{
				ID:   testID,
				Name: testName,
				Data: testData,
				Type: models.SecretTypeFile,
			},
		}, total), nil)

	apitest.Handler(root.Handler()).
		Debug().
		Get("/secrets").
		QueryParams(map[string]string{
			"limit":  strconv.FormatUint(limit, 10),
			"offset": strconv.FormatUint(offset, 10),
		}).
		Expect(t).
		Status(http.StatusOK).
		Bodyf(`
		{
		  "success":true,
		  "result": [
		  	{
		 		"id":"%s",
		 		"name":"%s",
		 		"type":"file"
		  	}
		  ],
		  "pagination":{"limit":%d,"offset":%d,"total":%d}
		  
		}`, testID, testName, limit, offset, total).
		End()
}

func TestGetPage_Fails_Validate(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	tests := []struct {
		name    string
		request map[string]string
		status  int
		errs    []string
	}{
		{
			name:    "empty",
			request: map[string]string{},
			status:  http.StatusUnprocessableEntity,
			errs:    []string{"Field validation for 'Limit' failed on the 'required' tag"},
		},
		{
			name:    "not numeric",
			request: map[string]string{"offset": "a", "limit": "b"},
			status:  http.StatusBadRequest,
		},
		{
			name:    "offset < 0",
			request: map[string]string{"offset": "-1", "limit": "1"},
			status:  http.StatusBadRequest,
		},
		{
			name:    "imit < 1",
			request: map[string]string{"limit": "0"},
			status:  http.StatusUnprocessableEntity,
			errs: []string{
				// Validator recognizes 0 as a not setted value
				"Field validation for 'Limit' failed on the 'required' tag",
			},
		},
		{
			name:    "limit > 100",
			request: map[string]string{"limit": "101"},
			status:  http.StatusUnprocessableEntity,
			errs:    []string{"Field validation for 'Limit' failed on the 'lte' tag"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := gin.Default()
			secrets.AddRoutes(&root.RouterGroup, mocks.NewMockService(ctrl), guardMock)

			result := apitest.New(tt.name).
				Handler(root.Handler()).
				Debug().
				Get("/secrets").
				QueryParams(tt.request).
				Expect(t).
				Status(tt.status).
				End()

			if tt.status != http.StatusBadRequest {
				var response response.Response[any]
				result.JSON(&response)

				require.False(t, response.Success)
				require.Nil(t, response.Result)
				assert.ElementsMatch(t, tt.errs, response.Errors)
			}
		})
	}
}

func TestGetPage_Fails_GetPage(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	root := gin.Default()
	service := mocks.NewMockService(ctrl)
	secrets.AddRoutes(&root.RouterGroup, service, guardMock)

	service.EXPECT().
		GetPage(gomock.Any(), testOwnerID, gomock.Any(), gomock.Any()).
		Return(nil, testutils.Err)

	apitest.Handler(root.Handler()).
		Debug().
		Get("/secrets").
		QueryParams(map[string]string{"page": "1", "limit": "1"}).
		Expect(t).
		Status(http.StatusInternalServerError).
		End()
}
