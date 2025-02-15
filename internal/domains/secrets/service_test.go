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
	testID        = models.SecretID("secret-id")
	testOwnerID   = models.UserID("owner-id")
	testSecretKey = "secret-key"
	testName      = "test-name"
)

var (
	testContent = []byte("content")
	testHash    = []byte("hash")
)

func TestService_Get_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := secrets.NewService(repo, nil, nil)

	got := &models.Secret{Owner: &models.User{ID: testOwnerID}}
	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(got, nil)

	want, err := service.Get(context.Background(), testID, testOwnerID)
	require.NoError(t, err)
	assert.Equal(t, want, got)
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

			_, err := service.Get(context.Background(), testID, testOwnerID)
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

	_, err := service.Get(context.Background(), testID, testOwnerID)
	assert.ErrorIs(t, err, secrets.ErrAnotherOwner)
}

func TestService_GetPage_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := secrets.NewService(repo, nil, nil)

	var page, limit uint64 = 1, 10
	got := &secrets.Page[models.Secret]{
		Items: []models.Secret{},
		Pages: 100,
	}

	repo.EXPECT().
		GetPage(gomock.Any(), testOwnerID, page, limit).
		Return(got, nil)

	want, err := service.GetPage(context.Background(), testOwnerID, page, limit)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestService_GetPage_Fails(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	service := secrets.NewService(repo, nil, nil)

	var page, limit uint64 = 1, 10

	repo.EXPECT().
		GetPage(gomock.Any(), testOwnerID, page, limit).
		Return(nil, testutils.Err)

	_, err := service.GetPage(context.Background(), testOwnerID, page, limit)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Create_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	encryptorFactory := mocks.NewMockEncryptorFactory(ctrl)
	service := secrets.NewService(repo, hasher, encryptorFactory)

	owner := &models.User{SecretKeyHash: testHash}
	repo.EXPECT().
		GetOwner(gomock.Any(), testOwnerID).
		Return(owner, nil)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(testHash, nil)

	encryptor := mocks.NewMockEncryptor(ctrl)
	encryptorFactory.EXPECT().Create(testSecretKey).Return(encryptor)
	encryptor.EXPECT().Encrypt(testutils.STRING).Return(testContent, nil)

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

	id, err := service.Create(context.Background(), testOwnerID, testSecretKey, testName, data)
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

	_, err := service.Create(context.Background(), testOwnerID, testSecretKey, testName, nil)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Create_Fails_Hash(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := secrets.NewService(repo, hasher, nil)

	repo.EXPECT().
		GetOwner(gomock.Any(), testOwnerID).
		Return(&models.User{SecretKeyHash: testHash}, nil)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(nil, testutils.Err)

	_, err := service.Create(context.Background(), testOwnerID, testSecretKey, testName, nil)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Create_Fails_CheckSecretKey(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := secrets.NewService(repo, hasher, nil)

	repo.EXPECT().
		GetOwner(gomock.Any(), testOwnerID).
		Return(&models.User{SecretKeyHash: []byte("other")}, nil)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(testHash, nil)

	_, err := service.Create(context.Background(), testOwnerID, testSecretKey, testName, nil)
	assert.ErrorIs(t, err, secrets.ErrInvalidSecretKey)
}

func TestService_Create_Fails_Encrypt(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	encryptorFactory := mocks.NewMockEncryptorFactory(ctrl)
	service := secrets.NewService(repo, hasher, encryptorFactory)

	repo.EXPECT().
		GetOwner(gomock.Any(), testOwnerID).
		Return(&models.User{SecretKeyHash: testHash}, nil)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(testHash, nil)

	encryptor := mocks.NewMockEncryptor(ctrl)
	encryptorFactory.EXPECT().Create(testSecretKey).Return(encryptor)
	encryptor.EXPECT().Encrypt(testutils.STRING).Return(nil, testutils.Err)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().ToString().Return(testutils.STRING)

	_, err := service.Create(context.Background(), testOwnerID, testSecretKey, testName, data)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Create_Fails_Create(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	encryptorFactory := mocks.NewMockEncryptorFactory(ctrl)
	service := secrets.NewService(repo, hasher, encryptorFactory)

	owner := &models.User{SecretKeyHash: testHash}
	repo.EXPECT().
		GetOwner(gomock.Any(), testOwnerID).
		Return(owner, nil)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(testHash, nil)

	encryptor := mocks.NewMockEncryptor(ctrl)
	encryptorFactory.EXPECT().Create(testSecretKey).Return(encryptor)
	encryptor.EXPECT().Encrypt(testutils.STRING).Return(testContent, nil)

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
		Return("", testutils.Err)

	_, err := service.Create(context.Background(), testOwnerID, testSecretKey, testName, data)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Update_Success(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	encryptorFactory := mocks.NewMockEncryptorFactory(ctrl)
	service := secrets.NewService(repo, hasher, encryptorFactory)

	secret := &models.Secret{
		Name:  testutils.STRING,
		Type:  models.SecretTypePwd,
		Data:  []byte(testutils.UNKNOWN),
		Owner: &models.User{ID: testOwnerID, SecretKeyHash: testHash},
	}
	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(secret, nil)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().SecretType().Return(secret.Type)
	data.EXPECT().ToString().Return(testutils.STRING)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(testHash, nil)

	encryptor := mocks.NewMockEncryptor(ctrl)
	encryptorFactory.EXPECT().Create(testSecretKey).Return(encryptor)
	encryptor.EXPECT().Encrypt(testutils.STRING).Return(testContent, nil)

	repo.EXPECT().
		Update(gomock.Any(), testID, &models.Secret{
			Name:  testName,
			Type:  secret.Type,
			Data:  testContent,
			Owner: secret.Owner,
		}).
		Return(nil)

	err := service.Update(context.Background(), testID, testOwnerID, testSecretKey, testName, data)
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

	err := service.Update(context.Background(), testID, testOwnerID, testSecretKey, testName, nil)
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
		Owner: &models.User{ID: testOwnerID, SecretKeyHash: testHash},
	}

	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(secret, nil)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().SecretType().Return(0)

	err := service.Update(context.Background(), testID, testOwnerID, testSecretKey, testName, data)
	assert.ErrorIs(t, err, secrets.ErrInvalidSecretType)
}

func TestService_Update_Fails_CheckSecretKey(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	service := secrets.NewService(repo, hasher, nil)

	secret := &models.Secret{
		Type:  models.SecretTypePwd,
		Owner: &models.User{ID: testOwnerID, SecretKeyHash: []byte("other")},
	}
	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(secret, nil)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().SecretType().Return(secret.Type)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(testHash, nil)

	err := service.Update(context.Background(), testID, testOwnerID, testSecretKey, testName, data)
	assert.ErrorIs(t, err, secrets.ErrInvalidSecretKey)
}

func TestService_Update_Fails_Encrypt(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	encryptorFactory := mocks.NewMockEncryptorFactory(ctrl)
	service := secrets.NewService(repo, hasher, encryptorFactory)

	secret := &models.Secret{
		Name:  testutils.STRING,
		Type:  models.SecretTypePwd,
		Data:  []byte(testutils.UNKNOWN),
		Owner: &models.User{ID: testOwnerID, SecretKeyHash: testHash},
	}
	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(secret, nil)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().SecretType().Return(secret.Type)
	data.EXPECT().ToString().Return(testutils.STRING)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(testHash, nil)

	encryptor := mocks.NewMockEncryptor(ctrl)
	encryptorFactory.EXPECT().Create(testSecretKey).Return(encryptor)
	encryptor.EXPECT().Encrypt(testutils.STRING).Return(nil, testutils.Err)

	err := service.Update(context.Background(), testID, testOwnerID, testSecretKey, testName, data)
	assert.ErrorIs(t, err, testutils.Err)
}

func TestService_Update_Fails_Update(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	repo := mocks.NewMockRepository(ctrl)
	hasher := mocks.NewMockHasher(ctrl)
	encryptorFactory := mocks.NewMockEncryptorFactory(ctrl)
	service := secrets.NewService(repo, hasher, encryptorFactory)

	secret := &models.Secret{
		Name:  testutils.STRING,
		Type:  models.SecretTypePwd,
		Data:  []byte(testutils.UNKNOWN),
		Owner: &models.User{ID: testOwnerID, SecretKeyHash: testHash},
	}
	repo.EXPECT().
		Get(gomock.Any(), testID).
		Return(secret, nil)

	data := mocks.NewMockISecretData(ctrl)
	data.EXPECT().SecretType().Return(secret.Type)
	data.EXPECT().ToString().Return(testutils.STRING)

	hasher.EXPECT().
		Hash(testSecretKey).
		Return(testHash, nil)

	encryptor := mocks.NewMockEncryptor(ctrl)
	encryptorFactory.EXPECT().Create(testSecretKey).Return(encryptor)
	encryptor.EXPECT().Encrypt(testutils.STRING).Return(testContent, nil)

	repo.EXPECT().
		Update(gomock.Any(), testID, &models.Secret{
			Name:  testName,
			Type:  secret.Type,
			Data:  testContent,
			Owner: secret.Owner,
		}).
		Return(testutils.Err)

	err := service.Update(context.Background(), testID, testOwnerID, testSecretKey, testName, data)
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
