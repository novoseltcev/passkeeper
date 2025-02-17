package secrets_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/novoseltcev/passkeeper/internal/domains/secrets"
	"github.com/novoseltcev/passkeeper/internal/domains/secrets/mocks"
	"github.com/novoseltcev/passkeeper/internal/models"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
)

const (
	testID         = models.SecretID("secret-id")
	testOwnerID    = models.UserID("owner-id")
	testPassphrase = "test-passphrase"
	testName       = "test-name"
	testHash       = "hash"
)

var testContent = []byte("content")

func TestService_Get_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	enc := mocks.NewMockEncryptor(ctrl)
	service := secrets.NewService(repo, hasher, enc)

	got := &models.Secret{Data: testContent, Owner: &models.User{ID: testOwnerID, PassphraseHash: testHash}}
	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(got, nil)

	hasher.EXPECT().
		Compare(testHash, testPassphrase).
		Return(true, nil)

	enc.EXPECT().
		Decrypt([]byte(testPassphrase), got.Data).
		Return([]byte(testutils.STRING), nil)

	secret, err := service.Get(context.Background(), testID, testOwnerID, testPassphrase)
	require.NoError(t, err)
	assert.Equal(t, &models.Secret{
		Data:  []byte(testutils.STRING),
		Owner: &models.User{ID: testOwnerID, PassphraseHash: testHash},
	}, secret)
}

func TestService_Get_Fails_Get(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	tests := []struct {
		name string
		err  error
	}{
		{
			name: "not found",
			err:  secrets.ErrSecretNotFound,
		},
		{
			name: "other",
			err:  testutils.Err,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			repo := mocks.NewMockRepository(ctrl)
			service := secrets.NewService(repo, nil, nil)

			repo.EXPECT().
				Get(gomock.Any(), testID).
				Return(nil, tt.err)

			_, err := service.Get(context.Background(), testID, testOwnerID, testPassphrase)
			assert.ErrorIs(t, err, tt.err)
		})
	}
}

func TestService_Get_Fails_AnotherOwner(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := secrets.NewService(repo, nil, nil)

	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(&models.Secret{Owner: &models.User{ID: testutils.UNKNOWN}}, nil)

	_, err := service.Get(context.Background(), testID, testOwnerID, testPassphrase)
	assert.ErrorIs(t, err, secrets.ErrAnotherOwner)
}

func TestService_Get_Fails_CompareErr(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := secrets.NewService(repo, hasher, nil)

	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(&models.Secret{Owner: &models.User{ID: testOwnerID, PassphraseHash: testHash}}, nil)

	hasher.EXPECT().
		Compare(testHash, testPassphrase).
		Return(false, testutils.Err)

	_, err := service.Get(context.Background(), testID, testOwnerID, testPassphrase)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Get_Fails_CompareFail(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := secrets.NewService(repo, hasher, nil)

	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(&models.Secret{Owner: &models.User{ID: testOwnerID, PassphraseHash: testHash}}, nil)

	hasher.EXPECT().
		Compare(testHash, testPassphrase).
		Return(false, nil)

	_, err := service.Get(context.Background(), testID, testOwnerID, testPassphrase)
	assert.ErrorIs(t, err, secrets.ErrInvalidPassphrase)
}

func TestService_Get_Fails_Decrypt(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	enc := mocks.NewMockEncryptor(ctrl)
	service := secrets.NewService(repo, hasher, enc)

	got := &models.Secret{Data: testContent, Owner: &models.User{ID: testOwnerID, PassphraseHash: testHash}}
	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(got, nil)

	hasher.EXPECT().
		Compare(testHash, testPassphrase).
		Return(true, nil)

	enc.EXPECT().
		Decrypt([]byte(testPassphrase), got.Data).
		Return(nil, testutils.Err)

	_, err := service.Get(context.Background(), testID, testOwnerID, testPassphrase)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_GetPage_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := secrets.NewService(repo, nil, nil)

	var limit, offset uint64 = 10, 0
	got := &secrets.Page[models.Secret]{
		Items: []models.Secret{},
		Total: 100,
	}

	repo.EXPECT().
		GetPage(gomock.Any(), testOwnerID, limit, offset).
		Return(got, nil)

	want, err := service.GetPage(context.Background(), testOwnerID, limit, offset)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestService_GetPage_Fails(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := secrets.NewService(repo, nil, nil)

	var limit, offset uint64 = 10, 0

	repo.EXPECT().
		GetPage(gomock.Any(), testOwnerID, limit, offset).
		Return(nil, testutils.Err)

	_, err := service.GetPage(context.Background(), testOwnerID, limit, offset)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Create_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	enc := mocks.NewMockEncryptor(ctrl)
	service := secrets.NewService(repo, hasher, enc)

	owner := &models.User{PassphraseHash: testHash}
	repo.EXPECT().
		GetOwner(gomock.Any(), testOwnerID).
		Return(owner, nil)

	hasher.EXPECT().
		Compare(owner.PassphraseHash, testPassphrase).
		Return(true, nil)

	enc.EXPECT().
		Encrypt([]byte(testPassphrase), []byte(testutils.STRING)).
		Return(testContent, nil)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().ToString().Return(testutils.STRING)
	data.EXPECT().SecretType().Return(models.SecretTypePwd)

	repo.EXPECT().
		Create(gomock.Any(), &models.Secret{
			Name:  testName,
			Type:  models.SecretTypePwd,
			Data:  testContent,
			Owner: owner,
		}).
		Return(testID, nil)

	id, err := service.Create(context.Background(), testOwnerID, testPassphrase, testName, data)
	require.NoError(t, err)
	assert.Equal(t, testID, id)
}

func TestService_Create_Fails_Get(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := secrets.NewService(repo, nil, nil)

	repo.EXPECT().
		GetOwner(gomock.Any(), testOwnerID).
		Return(nil, testutils.Err)

	_, err := service.Create(context.Background(), testOwnerID, testPassphrase, testName, nil)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Create_Fails_HashErr(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := secrets.NewService(repo, hasher, nil)

	repo.EXPECT().
		GetOwner(gomock.Any(), testOwnerID).
		Return(&models.User{PassphraseHash: testHash}, nil)

	hasher.EXPECT().
		Compare(testHash, testPassphrase).
		Return(false, testutils.Err)

	_, err := service.Create(context.Background(), testOwnerID, testPassphrase, testName, nil)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Create_Fails_Compare(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := secrets.NewService(repo, hasher, nil)

	repo.EXPECT().
		GetOwner(gomock.Any(), testOwnerID).
		Return(&models.User{PassphraseHash: testHash}, nil)

	hasher.EXPECT().
		Compare(testHash, testPassphrase).
		Return(false, nil)

	_, err := service.Create(context.Background(), testOwnerID, testPassphrase, testName, nil)
	assert.ErrorIs(t, err, secrets.ErrInvalidPassphrase)
}

func TestService_Create_Fails_Encrypt(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	enc := mocks.NewMockEncryptor(ctrl)
	service := secrets.NewService(repo, hasher, enc)

	repo.EXPECT().
		GetOwner(gomock.Any(), testOwnerID).
		Return(&models.User{PassphraseHash: testHash}, nil)

	hasher.EXPECT().
		Compare(testHash, testPassphrase).
		Return(true, nil)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().ToString().Return(testutils.STRING)
	enc.EXPECT().
		Encrypt([]byte(testPassphrase), []byte(testutils.STRING)).
		Return(nil, testutils.Err)

	_, err := service.Create(context.Background(), testOwnerID, testPassphrase, testName, data)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Create_Fails_Create(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	enc := mocks.NewMockEncryptor(ctrl)
	service := secrets.NewService(repo, hasher, enc)

	owner := &models.User{PassphraseHash: testHash}
	repo.EXPECT().
		GetOwner(gomock.Any(), testOwnerID).
		Return(owner, nil)

	hasher.EXPECT().
		Compare(owner.PassphraseHash, testPassphrase).
		Return(true, nil)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().ToString().Return(testutils.STRING)
	enc.EXPECT().
		Encrypt([]byte(testPassphrase), []byte(testutils.STRING)).
		Return(testContent, nil)

	data.EXPECT().SecretType().Return(models.SecretTypePwd)

	repo.EXPECT().
		Create(gomock.Any(), &models.Secret{
			Name:  testName,
			Type:  models.SecretTypePwd,
			Data:  testContent,
			Owner: owner,
		}).
		Return("", testutils.Err)

	_, err := service.Create(context.Background(), testOwnerID, testPassphrase, testName, data)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Update_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	enc := mocks.NewMockEncryptor(ctrl)
	service := secrets.NewService(repo, hasher, enc)

	secret := &models.Secret{
		Name:  testutils.STRING,
		Type:  models.SecretTypePwd,
		Data:  []byte(testutils.UNKNOWN),
		Owner: &models.User{ID: testOwnerID, PassphraseHash: testHash},
	}
	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(secret, nil)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().ToString().Return(testutils.STRING)
	data.EXPECT().SecretType().Return(secret.Type)

	hasher.EXPECT().
		Compare(secret.Owner.PassphraseHash, testPassphrase).
		Return(true, nil)

	enc.EXPECT().
		Encrypt([]byte(testPassphrase), []byte(testutils.STRING)).
		Return(testContent, nil)

	repo.EXPECT().
		Update(gomock.Any(), testID, &models.Secret{
			Name:  testName,
			Type:  secret.Type,
			Data:  testContent,
			Owner: secret.Owner,
		}).
		Return(nil)

	err := service.Update(context.Background(), testID, testOwnerID, testPassphrase, testName, data)
	require.NoError(t, err)
}

func TestService_Update_Fails_Get(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := secrets.NewService(repo, nil, nil)

	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(nil, testutils.Err)

	err := service.Update(context.Background(), testID, testOwnerID, testPassphrase, testName, nil)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Update_Fails_CheckType(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := secrets.NewService(repo, nil, nil)

	secret := &models.Secret{
		Type:  models.SecretTypePwd,
		Owner: &models.User{ID: testOwnerID, PassphraseHash: testHash},
	}

	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(secret, nil)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().SecretType().Return(0)

	err := service.Update(context.Background(), testID, testOwnerID, testPassphrase, testName, data)
	assert.ErrorIs(t, err, secrets.ErrInvalidSecretType)
}

func TestService_Update_Fails_CheckPassphrase(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := secrets.NewService(repo, hasher, nil)

	secret := &models.Secret{
		Type:  models.SecretTypePwd,
		Owner: &models.User{ID: testOwnerID, PassphraseHash: testHash},
	}
	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(secret, nil)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().SecretType().Return(secret.Type)

	hasher.EXPECT().
		Compare(secret.Owner.PassphraseHash, testPassphrase).
		Return(false, nil)

	err := service.Update(context.Background(), testID, testOwnerID, testPassphrase, testName, data)
	assert.ErrorIs(t, err, secrets.ErrInvalidPassphrase)
}

func TestService_Update_Fails_Encrypt(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	enc := mocks.NewMockEncryptor(ctrl)
	service := secrets.NewService(repo, hasher, enc)

	secret := &models.Secret{
		Name:  testutils.STRING,
		Type:  models.SecretTypePwd,
		Data:  []byte(testutils.UNKNOWN),
		Owner: &models.User{ID: testOwnerID, PassphraseHash: testHash},
	}
	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(secret, nil)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().SecretType().Return(secret.Type)
	data.EXPECT().ToString().Return(testutils.STRING)

	hasher.EXPECT().
		Compare(secret.Owner.PassphraseHash, testPassphrase).
		Return(true, nil)

	enc.EXPECT().
		Encrypt([]byte(testPassphrase), []byte(testutils.STRING)).
		Return(nil, testutils.Err)

	err := service.Update(context.Background(), testID, testOwnerID, testPassphrase, testName, data)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Update_Fails_Update(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	enc := mocks.NewMockEncryptor(ctrl)
	service := secrets.NewService(repo, hasher, enc)

	secret := &models.Secret{
		Name:  testutils.STRING,
		Type:  models.SecretTypePwd,
		Data:  []byte(testutils.UNKNOWN),
		Owner: &models.User{ID: testOwnerID, PassphraseHash: testHash},
	}
	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(secret, nil)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().SecretType().Return(secret.Type)
	data.EXPECT().ToString().Return(testutils.STRING)

	hasher.EXPECT().
		Compare(secret.Owner.PassphraseHash, testPassphrase).
		Return(true, nil)

	enc.EXPECT().
		Encrypt([]byte(testPassphrase), []byte(testutils.STRING)).
		Return(testContent, nil)

	repo.EXPECT().
		Update(gomock.Any(), testID, &models.Secret{
			Name:  testName,
			Type:  secret.Type,
			Data:  testContent,
			Owner: secret.Owner,
		}).
		Return(testutils.Err)

	err := service.Update(context.Background(), testID, testOwnerID, testPassphrase, testName, data)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Delete_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := secrets.NewService(repo, nil, nil)

	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(&models.Secret{Owner: &models.User{ID: testOwnerID}}, nil)

	repo.EXPECT().
		Delete(gomock.Any(), testID).
		Return(nil)

	err := service.Delete(context.Background(), testID, testOwnerID)
	require.NoError(t, err)
}

func TestService_Delete_Fails_Get(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := secrets.NewService(repo, nil, nil)

	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(nil, testutils.Err)

	err := service.Delete(context.Background(), testID, testOwnerID)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Delete_Fails_AnotherOwner(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := secrets.NewService(repo, nil, nil)

	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(&models.Secret{Owner: &models.User{ID: testutils.UNKNOWN}}, nil)

	err := service.Delete(context.Background(), testID, testOwnerID)
	assert.ErrorIs(t, err, secrets.ErrAnotherOwner)
}

func TestService_Delete_Fails_Delete(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := secrets.NewService(repo, nil, nil)

	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(&models.Secret{Owner: &models.User{ID: testOwnerID}}, nil)

	repo.EXPECT().
		Delete(gomock.Any(), testID).
		Return(testutils.Err)

	err := service.Delete(context.Background(), testID, testOwnerID)
	assert.ErrorIs(t, err, testutils.Err)
}
