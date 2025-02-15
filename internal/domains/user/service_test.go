package user_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/novoseltcev/passkeeper/internal/domains/user"
	"github.com/novoseltcev/passkeeper/internal/domains/user/mocks"
	"github.com/novoseltcev/passkeeper/internal/models"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
)

const (
	testID        = models.UserID("test-id")
	testLogin     = "test-login"
	testPassword  = "test-password"
	testSecretKey = "test-secret-key"
)

var (
	testPasswordHash  = []byte("password-hash")
	testSecretKeyHash = []byte("secret-hash")
)

func TestService_Login_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := user.NewService(repo, hasher)

	repo.EXPECT().
		GetByLogin(gomock.Any(), testLogin).
		Return(&models.User{
			ID:           testID,
			PasswordHash: testPasswordHash,
		}, nil)

	hasher.EXPECT().
		Hash(testPassword).
		Return(testPasswordHash, nil)

	id, err := service.Login(context.Background(), testLogin, testPassword)
	require.NoError(t, err)
	assert.Equal(t, testID, id)
}

func TestService_Login_Fails_Get(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	tests := []struct {
		name string
		got  error
		want error
	}{
		{
			name: "not found",
			got:  user.ErrUserNotFound,
			want: user.ErrAutenticationFailed,
		},
		{
			name: "other",
			got:  testutils.Err,
			want: testutils.Err,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repo := mocks.NewMockRepository(ctrl)
			service := user.NewService(repo, nil)

			repo.EXPECT().
				GetByLogin(gomock.Any(), testLogin).
				Return(nil, tt.got)

			_, err := service.Login(context.Background(), testLogin, testPassword)
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestService_Login_Fails_Hash(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := user.NewService(repo, hasher)

	repo.EXPECT().
		GetByLogin(gomock.Any(), testLogin).
		Return(&models.User{}, nil)

	hasher.EXPECT().
		Hash(testPassword).
		Return(nil, testutils.Err)

	_, err := service.Login(context.Background(), testLogin, testPassword)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Login_Fails_CheckPassword(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := user.NewService(repo, hasher)

	repo.EXPECT().
		GetByLogin(gomock.Any(), testLogin).
		Return(&models.User{
			ID:           testID,
			PasswordHash: []byte("other"),
		}, nil)

	hasher.EXPECT().
		Hash(testPassword).
		Return(testPasswordHash, nil)

	_, err := service.Login(context.Background(), testLogin, testPassword)
	assert.ErrorIs(t, err, user.ErrAutenticationFailed)
}

func TestService_Register_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := user.NewService(repo, hasher)

	repo.EXPECT().
		GetByLogin(gomock.Any(), testLogin).
		Return(nil, user.ErrUserNotFound)

	hasher.EXPECT().
		Hash(testPassword).
		Return(testPasswordHash, nil)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(testSecretKeyHash, nil)

	repo.EXPECT().
		CreateAccount(gomock.Any(), &models.User{
			Login:         testLogin,
			PasswordHash:  testPasswordHash,
			SecretKeyHash: testSecretKeyHash,
		}).
		Return(testID, nil)

	id, err := service.Register(context.Background(), testLogin, testPassword, testSecretKey)
	require.NoError(t, err)
	assert.Equal(t, testID, id)
}

func TestService_Register_Fails_Get(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := user.NewService(repo, nil)

	repo.EXPECT().
		GetByLogin(gomock.Any(), testLogin).
		Return(nil, testutils.Err)

	_, err := service.Register(context.Background(), testLogin, testPassword, testSecretKey)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Register_Fails_LoginIsBusy(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := user.NewService(repo, nil)

	repo.EXPECT().
		GetByLogin(gomock.Any(), testLogin).
		Return(&models.User{}, nil)

	_, err := service.Register(context.Background(), testLogin, testPassword, testSecretKey)
	assert.ErrorIs(t, err, user.ErrLoginIsBusy)
}

func TestService_Register_Fails_HashPassword(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := user.NewService(repo, hasher)

	repo.EXPECT().
		GetByLogin(gomock.Any(), testLogin).
		Return(nil, user.ErrUserNotFound)

	hasher.EXPECT().
		Hash(testPassword).
		Return(nil, testutils.Err)

	_, err := service.Register(context.Background(), testLogin, testPassword, testSecretKey)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Register_Fails_HashSecretKey(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := user.NewService(repo, hasher)

	repo.EXPECT().
		GetByLogin(gomock.Any(), testLogin).
		Return(nil, user.ErrUserNotFound)

	hasher.EXPECT().
		Hash(testPassword).
		Return(testPasswordHash, nil)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(nil, testutils.Err)

	_, err := service.Register(context.Background(), testLogin, testPassword, testSecretKey)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Register_Fails_Create(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := user.NewService(repo, hasher)

	repo.EXPECT().
		GetByLogin(gomock.Any(), testLogin).
		Return(nil, user.ErrUserNotFound)

	hasher.EXPECT().
		Hash(testPassword).
		Return(testPasswordHash, nil)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(testSecretKeyHash, nil)

	repo.EXPECT().
		CreateAccount(gomock.Any(), &models.User{
			Login:         testLogin,
			PasswordHash:  testPasswordHash,
			SecretKeyHash: testSecretKeyHash,
		}).
		Return("", testutils.Err)

	_, err := service.Register(context.Background(), testLogin, testPassword, testSecretKey)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_VerifySecret_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := user.NewService(repo, hasher)

	repo.EXPECT().
		GetByID(gomock.Any(), testID).
		Return(&models.User{
			ID:            testID,
			SecretKeyHash: testSecretKeyHash,
		}, nil)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(testSecretKeyHash, nil)

	err := service.VerifySecret(context.Background(), testID, testSecretKey)
	require.NoError(t, err)
}

func TestService_VerifySecret_Fails_Get(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := user.NewService(repo, nil)

	repo.EXPECT().
		GetByID(gomock.Any(), testID).
		Return(nil, testutils.Err)

	err := service.VerifySecret(context.Background(), testID, testSecretKey)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_VerifySecret_Fails_Hash(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := user.NewService(repo, hasher)

	repo.EXPECT().
		GetByID(gomock.Any(), testID).
		Return(&models.User{}, nil)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(nil, testutils.Err)

	err := service.VerifySecret(context.Background(), testID, testSecretKey)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_VerifySecret_Fails_CheckSecretKey(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := user.NewService(repo, hasher)

	repo.EXPECT().
		GetByID(gomock.Any(), testID).
		Return(&models.User{
			ID:            testID,
			SecretKeyHash: []byte("other"),
		}, nil)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(testSecretKeyHash, nil)

	err := service.VerifySecret(context.Background(), testID, testSecretKey)
	assert.ErrorIs(t, err, user.ErrInvalidSecretKey)
}
