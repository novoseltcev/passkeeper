package jwtmanager_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/novoseltcev/passkeeper/pkg/jwtmanager"
	"github.com/novoseltcev/passkeeper/pkg/jwtmanager/mocks"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
)

const (
	testKey         = "testKey"
	testIssuer      = "testIssuer"
	testTokenString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjo5OTk5OTk5OTk5OSwiaXNzIjoidGVzdElzc3VlciIsImp0aSI6ImYyMTZiOTk3LTY3N2EtNDI0ZS1hNjNmLTJlODBjYTNiYTZiOSJ9.gMEGtr7XBQvqZlLOV83rl6s3qaP2oS8eKOJCmovJJRE" // nolint: lll
)

func decodeTokenPart(t *testing.T, part string) map[string]any {
	t.Helper()

	val, err := base64.RawURLEncoding.DecodeString(part)
	require.NoError(t, err)

	var data map[string]any
	require.NoError(t, json.Unmarshal(val, &data))

	return data
}

func decodeToken(t *testing.T, tokenString string) (map[string]any, map[string]any) {
	t.Helper()

	parts := strings.Split(tokenString, ".")
	require.Len(t, parts, 3)

	return decodeTokenPart(t, parts[0]), decodeTokenPart(t, parts[1])
}

func TestManager_GenerateToken_Success(t *testing.T) {
	t.Parallel()

	t.Run("default", func(t *testing.T) {
		t.Parallel()

		mngr := jwtmanager.New(testKey)

		token, err := mngr.GenerateToken(context.Background(), testutils.STRING)
		require.NoError(t, err)

		header, payload := decodeToken(t, token)
		assert.Equal(t, map[string]any{"typ": "JWT", "alg": "HS256"}, header)
		assert.Equal(t, map[string]any{
			"sub": testutils.STRING,
			"exp": float64(time.Now().Add(time.Hour * 24 * 7).Unix()),
			"iat": float64(time.Now().Unix()),
		}, payload)
	})

	t.Run("custom", func(t *testing.T) {
		t.Parallel()

		mngr := jwtmanager.New(testKey,
			jwtmanager.WithAlgorithm(jwt.SigningMethodHS512),
			jwtmanager.WithExpiration(time.Hour),
			jwtmanager.WithIssuer(testIssuer),
		)

		token, err := mngr.GenerateToken(context.Background(), testutils.STRING)
		require.NoError(t, err)

		parts := strings.Split(token, ".")
		require.Len(t, parts, 3)

		header, payload := decodeToken(t, token)

		assert.Equal(t, map[string]any{"typ": "JWT", "alg": "HS512"}, header)
		assert.Equal(t, map[string]any{
			"sub": testutils.STRING,
			"exp": float64(time.Now().Add(time.Hour).Unix()),
			"iat": float64(time.Now().Unix()),
			"iss": testIssuer,
		}, payload)
	})

	t.Run("with storage", func(t *testing.T) {
		t.Parallel()
		ctrl := gomock.NewController(t)
		t.Cleanup(ctrl.Finish)

		storage := mocks.NewMockTokenStorager(ctrl)

		var jti string
		storage.EXPECT().
			Store(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, token jwtmanager.Token) error {
				jti = token.ID

				return nil
			})

		mngr := jwtmanager.New(testKey, jwtmanager.WithTokenStorage(storage))

		token, err := mngr.GenerateToken(context.Background(), testutils.STRING)
		require.NoError(t, err)

		parts := strings.Split(token, ".")
		require.Len(t, parts, 3)

		_, payload := decodeToken(t, token)
		assert.Equal(t, jti, payload["jti"])
	})
}

func TestManager_WithStorager_GenerateToken_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	storage := mocks.NewMockTokenStorager(ctrl)

	var jti string
	storage.EXPECT().
		Store(gomock.Any(), gomock.Any()).
		DoAndReturn(func(_ context.Context, token jwtmanager.Token) error {
			jti = token.ID

			return nil
		})

	mngr := jwtmanager.New(testKey, jwtmanager.WithTokenStorage(storage))

	token, err := mngr.GenerateToken(context.Background(), testutils.STRING)
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	_, payload := decodeToken(t, token)
	assert.Equal(t, jti, payload["jti"])
}

func TestManager_WithStorager_GenerateToken_Fails_Save(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	storage := mocks.NewMockTokenStorager(ctrl)
	storage.EXPECT().
		Store(gomock.Any(), gomock.Any()).
		Return(testutils.Err)

	mngr := jwtmanager.New(testKey, jwtmanager.WithTokenStorage(storage))

	_, err := mngr.GenerateToken(context.Background(), testutils.STRING)
	require.ErrorIs(t, err, testutils.Err)
}

func TestManager_GenerateToken_Fails_Expired(t *testing.T) {
	t.Parallel()

	mngr := jwtmanager.New(testutils.STRING, jwtmanager.WithExpiration(time.Microsecond))

	_, err := mngr.GenerateToken(context.Background(), testutils.STRING)
	assert.ErrorIs(t, err, jwt.ErrTokenExpired)
}

func TestManager_ParseToken_Success(t *testing.T) {
	t.Parallel()

	now := time.Now()
	duration := time.Hour
	exp, err := time.Parse(time.RFC3339, now.Add(duration).Format(time.RFC3339))
	require.NoError(t, err)

	mngr := jwtmanager.New(testKey,
		jwtmanager.WithExpiration(duration),
		jwtmanager.WithIssuer(testIssuer),
	)

	tokenString, err := mngr.GenerateToken(context.Background(), testutils.STRING)
	require.NoError(t, err)

	token, err := mngr.ParseToken(context.Background(), tokenString)
	require.NoError(t, err)

	assert.Equal(t, &jwtmanager.Token{
		ID:        "",
		Subject:   testutils.STRING,
		ExpiresAt: exp,
	}, token)
}

func TestManager_WithStorage_ParseToken_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	storage := mocks.NewMockTokenStorager(ctrl)
	mngr := jwtmanager.New(testKey, jwtmanager.WithTokenStorage(storage))

	storage.EXPECT().Store(gomock.Any(), gomock.Any()).Return(nil)
	tokenString, err := mngr.GenerateToken(context.Background(), testutils.STRING)
	require.NoError(t, err)

	storage.EXPECT().Load(gomock.Any(), gomock.Any()).Return(nil, nil)
	token, err := mngr.ParseToken(context.Background(), tokenString)
	require.NoError(t, err)

	_, payload := decodeToken(t, tokenString)
	assert.Equal(t, payload["jti"], token.ID)
}

func TestManager_ParseToken_Fails(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	tests := []struct {
		name        string
		tokenString string
		err         error
	}{
		{name: "count segments <3", tokenString: "1.2", err: jwt.ErrTokenMalformed},
		{name: "count segments >3", tokenString: "1.2.3.4", err: jwt.ErrTokenMalformed},
		{name: "invalid base64 encoding", tokenString: "1.2.3", err: jwt.ErrTokenMalformed},
		{
			name:        "invalid algorithm",
			tokenString: "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.fH8kWlGE7_Ki6pPltGFwIBKWuDobSQPcrIkBgmyvog01VMnNo-VFjug2AiySZkzV", // nolint: lll
			err:         jwt.ErrTokenSignatureInvalid,
		},
		{
			name:        "invalid key",
			tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.LwimMJA3puF3ioGeS-tfczR3370GXBZMIL-bdpu4hOU",
			err:         jwt.ErrTokenSignatureInvalid,
		},
		{
			name:        "expired",
			tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjF9.K2uhBnei69lCZOYg7ClK7JiAyDeHOqlEuTJSBAs0kGM",
			err:         jwt.ErrTokenExpired,
		},
		{
			name:        "without sub",
			tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.PyJpI17-b9uKZnUGk5YEzRPDYsA-8cNiT7crKGIHfBs",
			err:         jwtmanager.ErrTokenInvalidSubject,
		},
		{
			name:        "without exp",
			tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.YfzQWBNHTOUr8i5znrGk6lPHD9DfvNGop7UjNQKE-U0",
			err:         jwtmanager.ErrTokenWithoutExpiration,
		},
		{
			name:        "without iss",
			tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjo5OTk5OTk5OTk5OX0.AP8nTU5y_t8WC6YxRzcNxQ8hyyXFz-qsmk7kAI1uAvk", // nolint: lll
			err:         jwt.ErrTokenInvalidIssuer,
		},
		{
			name:        "without jti",
			tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjo5OTk5OTk5OTk5OSwiaXNzIjoidGVzdElzc3VlciJ9.zXWrlWG2FVJbwwv26MoXvdlOVCojb5vIwSNT22tTRDU", // nolint: lll
			err:         jwt.ErrTokenInvalidId,
		},
		{
			name:        "not uuid jti",
			tokenString: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjo5OTk5OTk5OTk5OSwiaXNzIjoidGVzdElzc3VlciIsImp0aSI6InNvbWUifQ._ybBnO9eo7COvzv01HSQThsEXOhyPvhkoAKOa8OMtxA", // nolint: lll
			err:         jwt.ErrTokenInvalidId,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mngr := jwtmanager.New(testKey,
				jwtmanager.WithIssuer(testIssuer),
				jwtmanager.WithTokenStorage(mocks.NewMockTokenStorager(ctrl)),
			)

			_, err := mngr.ParseToken(context.Background(), tt.tokenString)
			assert.ErrorIs(t, err, tt.err)
		})
	}
}

func TestManager_ParseToken_Fails_UnknownLoadError(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	storage := mocks.NewMockTokenStorager(ctrl)
	mngr := jwtmanager.New(testKey, jwtmanager.WithTokenStorage(storage))

	storage.EXPECT().Load(gomock.Any(), gomock.Any()).Return(nil, testutils.Err)

	_, err := mngr.ParseToken(context.Background(), testTokenString)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestManager_ParseToken_Fails_NotFound(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	storage := mocks.NewMockTokenStorager(ctrl)
	mngr := jwtmanager.New(testKey, jwtmanager.WithTokenStorage(storage))

	storage.EXPECT().Load(gomock.Any(), gomock.Any()).Return(nil, jwtmanager.ErrTokenNotFound)

	_, err := mngr.ParseToken(context.Background(), testTokenString)
	require.ErrorIs(t, err, jwtmanager.ErrTokenNotFound)
	assert.ErrorIs(t, err, jwt.ErrTokenExpired)
}
