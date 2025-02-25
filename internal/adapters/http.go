package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/novoseltcev/passkeeper/internal/controllers/http/common/response"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/secrets"
	"github.com/novoseltcev/passkeeper/internal/controllers/http/v1/user"
)

type HTTP struct {
	client  *http.Client
	baseURL string
}

var _ API = (*HTTP)(nil)

func NewHTTP(client *http.Client, baseURL string) *HTTP {
	return &HTTP{client: client, baseURL: baseURL}
}

func (a *HTTP) doRequest(req *http.Request, codes []int) ([]byte, error) {
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}

	var body []byte

	if resp.Body != nil {
		defer resp.Body.Close()

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	}

	for _, code := range codes {
		if resp.StatusCode == code {
			return body, nil
		}
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}

	return body, fmt.Errorf("failed to get response: %s", resp.Status)
}

func (a *HTTP) GetSecretsPage(
	ctx context.Context,
	token string,
	params *secrets.PaginationRequest,
) ([]secrets.SecretItemSchema, uint64, error) {
	v := make(url.Values)
	v.Set("limit", fmt.Sprint(params.Limit))
	v.Set("offset", fmt.Sprint(params.Offset))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.baseURL+"/api/v1/secrets?"+v.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	body, err := a.doRequest(req, []int{http.StatusOK})
	if err != nil {
		return nil, 0, err
	}

	var schema response.PaginatedResponse[secrets.SecretItemSchema]
	if err := json.Unmarshal(body, &schema); err != nil {
		return nil, 0, err
	}

	if !schema.Success {
		return nil, 0, fmt.Errorf("failed to get secrets page: %s", schema.Errors)
	}

	return schema.Result, schema.Pagination.Total, nil
}

func (a *HTTP) DecryptSecret(
	ctx context.Context,
	token, uuid string,
	data *secrets.DecryptByIDData,
) (*secrets.SecretSchema, error) {
	reqBody, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.baseURL+"/api/v1/secrets/"+uuid+"/decrypt",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	body, err := a.doRequest(req, []int{http.StatusOK})
	if err != nil {
		return nil, err
	}

	var schema response.Response[secrets.SecretSchema]
	if err := json.Unmarshal(body, &schema); err != nil {
		return nil, err
	}

	if !schema.Success {
		return nil, fmt.Errorf("failed to decrypt secret: %s", schema.Errors)
	}

	return schema.Result, nil
}

func (a *HTTP) Add(ctx context.Context, token string, data any) (string, error) {
	reqBody, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	var secretType string
	switch data.(type) {
	case *secrets.PasswordSecretData:
		secretType = "password"
	case *secrets.CardSecretData:
		secretType = "card"
	case *secrets.TextSecretData:
		secretType = "text"
	case *secrets.FileSecretData:
		secretType = "file"
	default:
		return "", fmt.Errorf("unknown secret type")
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.baseURL+"/api/v1/secrets/"+secretType,
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	body, err := a.doRequest(req, []int{http.StatusCreated})
	if err != nil {
		return "", err
	}

	var schema response.Response[secrets.SecretSchema]
	if err := json.Unmarshal(body, &schema); err != nil {
		return "", err
	}

	if !schema.Success {
		return "", fmt.Errorf("failed to add secret: %s", schema.Errors)
	}

	return schema.Result.ID, nil
}

func (a *HTTP) Update(ctx context.Context, token string, uuid string, data any) error {
	reqBody, err := json.Marshal(data)
	if err != nil {
		return err
	}

	var secretType string
	switch data.(type) {
	case *secrets.PasswordSecretData:
		secretType = "password"
	case *secrets.CardSecretData:
		secretType = "card"
	case *secrets.TextSecretData:
		secretType = "text"
	case *secrets.FileSecretData:
		secretType = "file"
	default:
		return fmt.Errorf("unknown secret type")
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPut,
		a.baseURL+"/api/v1/secrets/"+secretType+"/"+uuid,
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	body, err := a.doRequest(req, []int{http.StatusCreated})
	if err != nil {
		return err
	}

	var schema response.Response[secrets.SecretSchema]
	if err := json.Unmarshal(body, &schema); err != nil {
		return err
	}

	if !schema.Success {
		return fmt.Errorf("failed to update secret: %s", schema.Errors)
	}

	return nil
}

func (a *HTTP) DeleteSecret(ctx context.Context, token string, uuid string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, a.baseURL+"/api/v1/secrets/"+uuid, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	_, err = a.doRequest(req, []int{http.StatusNoContent})

	return err
}

func (a *HTTP) Login(ctx context.Context, data *user.LoginData) (string, error) { // nolint: dupl
	reqBody, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.baseURL+"/api/v1/user/login",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/json")

	body, err := a.doRequest(req, []int{http.StatusOK})
	if err != nil {
		return "", err
	}

	var schema response.Response[user.LoginBody]
	if err := json.Unmarshal(body, &schema); err != nil {
		return "", err
	}

	if !schema.Success {
		return "", fmt.Errorf("failed to login: %s", schema.Errors)
	}

	return schema.Result.Token, nil
}

func (a *HTTP) Register(ctx context.Context, data *user.RegisterData) (string, error) { // nolint: dupl
	reqBody, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.baseURL+"/api/v1/user/register",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/json")

	body, err := a.doRequest(req, []int{http.StatusCreated})
	if err != nil {
		return "", err
	}

	var schema response.Response[user.RegisterBody]
	if err := json.Unmarshal(body, &schema); err != nil {
		return "", err
	}

	if !schema.Success {
		return "", fmt.Errorf("failed to register: %s", schema.Errors)
	}

	return schema.Result.Token, nil
}

func (a *HTTP) Verify(ctx context.Context, token string, data *user.VerifyData) error {
	reqBody, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.baseURL+"/api/v1/user/verify-secret",
		bytes.NewBuffer(reqBody),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	_, err = a.doRequest(req, []int{http.StatusNoContent})

	return err
}
