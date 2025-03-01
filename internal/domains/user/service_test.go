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
	testID             = models.UserID("test-id")
	testLogin          = "test-login"
	testPassword       = "test-password"
	testPassphrase     = "test-passphrase"
	testPasswordHash   = "password-hash"
	testPassphraseHash = "passphrase-hash"
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
		Compare(testPasswordHash, testPassword).
		Return(true, nil)

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
			want: user.ErrAuthenticationFailed,
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

func TestService_Login_Fails_HashErr(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := user.NewService(repo, hasher)

	repo.EXPECT().
		GetByLogin(gomock.Any(), testLogin).
		Return(&models.User{PasswordHash: testPasswordHash}, nil)

	hasher.EXPECT().
		Compare(testPasswordHash, testPassword).
		Return(false, testutils.Err)

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
			PasswordHash: testPasswordHash,
		}, nil)

	hasher.EXPECT().
		Compare(testPasswordHash, testPassword).
		Return(false, nil)

	_, err := service.Login(context.Background(), testLogin, testPassword)
	assert.ErrorIs(t, err, user.ErrAuthenticationFailed)
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
		Generate(testPassword).
		Return(testPasswordHash, nil)

	hasher.EXPECT().
		Generate(testPassphrase).
		Return(testPassphraseHash, nil)

	repo.EXPECT().
		CreateAccount(gomock.Any(), &models.User{
			Login:          testLogin,
			PasswordHash:   testPasswordHash,
			PassphraseHash: testPassphraseHash,
		}).
		Return(testID, nil)

	id, err := service.Register(context.Background(), testLogin, testPassword, testPassphrase)
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

	_, err := service.Register(context.Background(), testLogin, testPassword, testPassphrase)
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

	_, err := service.Register(context.Background(), testLogin, testPassword, testPassphrase)
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
		Generate(testPassword).
		Return("", testutils.Err)

	_, err := service.Register(context.Background(), testLogin, testPassword, testPassphrase)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Register_Fails_HashPassphrase(t *testing.T) {
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
		Generate(testPassword).
		Return(testPasswordHash, nil)

	hasher.EXPECT().
		Generate(testPassphrase).
		Return("", testutils.Err)

	_, err := service.Register(context.Background(), testLogin, testPassword, testPassphrase)
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
		Generate(testPassword).
		Return(testPasswordHash, nil)

	hasher.EXPECT().
		Generate(testPassphrase).
		Return(testPassphraseHash, nil)

	repo.EXPECT().
		CreateAccount(gomock.Any(), &models.User{
			Login:          testLogin,
			PasswordHash:   testPasswordHash,
			PassphraseHash: testPassphraseHash,
		}).
		Return("", testutils.Err)

	_, err := service.Register(context.Background(), testLogin, testPassword, testPassphrase)
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
			ID:             testID,
			PassphraseHash: testPassphraseHash,
		}, nil)

	hasher.EXPECT().
		Compare(testPassphraseHash, testPassphrase).
		Return(true, nil)

	err := service.VerifyPassphrase(context.Background(), testID, testPassphrase)
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

	err := service.VerifyPassphrase(context.Background(), testID, testPassphrase)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_VerifySecret_Fails_HashErr(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := user.NewService(repo, hasher)

	repo.EXPECT().
		GetByID(gomock.Any(), testID).
		Return(&models.User{PassphraseHash: testPassphraseHash}, nil)

	hasher.EXPECT().
		Compare(testPassphraseHash, testPassphrase).
		Return(false, testutils.Err)

	err := service.VerifyPassphrase(context.Background(), testID, testPassphrase)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_VerifySecret_Fails_Compare(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := user.NewService(repo, hasher)

	repo.EXPECT().
		GetByID(gomock.Any(), testID).
		Return(&models.User{
			ID:             testID,
			PassphraseHash: testPassphraseHash,
		}, nil)

	hasher.EXPECT().
		Compare(testPassphraseHash, testPassphrase).
		Return(false, nil)

	err := service.VerifyPassphrase(context.Background(), testID, testPassphrase)
	assert.ErrorIs(t, err, user.ErrInvalidPassphrase)
}
