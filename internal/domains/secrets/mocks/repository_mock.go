// Code generated by MockGen. DO NOT EDIT.
// Source: repository.go
//
// Generated by this command:
//
//	mockgen -destination=mocks/repository_mock.go -package=mocks -source=repository.go -typed
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	secrets "github.com/novoseltcev/passkeeper/internal/domains/secrets"
	models "github.com/novoseltcev/passkeeper/internal/models"
	gomock "go.uber.org/mock/gomock"
)

// MockRepository is a mock of Repository interface.
type MockRepository struct {
	ctrl     *gomock.Controller
	recorder *MockRepositoryMockRecorder
	isgomock struct{}
}

// MockRepositoryMockRecorder is the mock recorder for MockRepository.
type MockRepositoryMockRecorder struct {
	mock *MockRepository
}

// NewMockRepository creates a new mock instance.
func NewMockRepository(ctrl *gomock.Controller) *MockRepository {
	mock := &MockRepository{ctrl: ctrl}
	mock.recorder = &MockRepositoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRepository) EXPECT() *MockRepositoryMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockRepository) Create(ctx context.Context, data *models.Secret) (models.SecretID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, data)
	ret0, _ := ret[0].(models.SecretID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockRepositoryMockRecorder) Create(ctx, data any) *MockRepositoryCreateCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockRepository)(nil).Create), ctx, data)
	return &MockRepositoryCreateCall{Call: call}
}

// MockRepositoryCreateCall wrap *gomock.Call
type MockRepositoryCreateCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRepositoryCreateCall) Return(arg0 models.SecretID, arg1 error) *MockRepositoryCreateCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRepositoryCreateCall) Do(f func(context.Context, *models.Secret) (models.SecretID, error)) *MockRepositoryCreateCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRepositoryCreateCall) DoAndReturn(f func(context.Context, *models.Secret) (models.SecretID, error)) *MockRepositoryCreateCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Delete mocks base method.
func (m *MockRepository) Delete(ctx context.Context, id models.SecretID) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Delete", ctx, id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete.
func (mr *MockRepositoryMockRecorder) Delete(ctx, id any) *MockRepositoryDeleteCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockRepository)(nil).Delete), ctx, id)
	return &MockRepositoryDeleteCall{Call: call}
}

// MockRepositoryDeleteCall wrap *gomock.Call
type MockRepositoryDeleteCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRepositoryDeleteCall) Return(arg0 error) *MockRepositoryDeleteCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRepositoryDeleteCall) Do(f func(context.Context, models.SecretID) error) *MockRepositoryDeleteCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRepositoryDeleteCall) DoAndReturn(f func(context.Context, models.SecretID) error) *MockRepositoryDeleteCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Get mocks base method.
func (m *MockRepository) Get(ctx context.Context, id models.SecretID) (*models.Secret, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Get", ctx, id)
	ret0, _ := ret[0].(*models.Secret)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Get indicates an expected call of Get.
func (mr *MockRepositoryMockRecorder) Get(ctx, id any) *MockRepositoryGetCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockRepository)(nil).Get), ctx, id)
	return &MockRepositoryGetCall{Call: call}
}

// MockRepositoryGetCall wrap *gomock.Call
type MockRepositoryGetCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRepositoryGetCall) Return(arg0 *models.Secret, arg1 error) *MockRepositoryGetCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRepositoryGetCall) Do(f func(context.Context, models.SecretID) (*models.Secret, error)) *MockRepositoryGetCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRepositoryGetCall) DoAndReturn(f func(context.Context, models.SecretID) (*models.Secret, error)) *MockRepositoryGetCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetOwner mocks base method.
func (m *MockRepository) GetOwner(ctx context.Context, ownerID models.UserID) (*models.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOwner", ctx, ownerID)
	ret0, _ := ret[0].(*models.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetOwner indicates an expected call of GetOwner.
func (mr *MockRepositoryMockRecorder) GetOwner(ctx, ownerID any) *MockRepositoryGetOwnerCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOwner", reflect.TypeOf((*MockRepository)(nil).GetOwner), ctx, ownerID)
	return &MockRepositoryGetOwnerCall{Call: call}
}

// MockRepositoryGetOwnerCall wrap *gomock.Call
type MockRepositoryGetOwnerCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRepositoryGetOwnerCall) Return(arg0 *models.User, arg1 error) *MockRepositoryGetOwnerCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRepositoryGetOwnerCall) Do(f func(context.Context, models.UserID) (*models.User, error)) *MockRepositoryGetOwnerCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRepositoryGetOwnerCall) DoAndReturn(f func(context.Context, models.UserID) (*models.User, error)) *MockRepositoryGetOwnerCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// GetPage mocks base method.
func (m *MockRepository) GetPage(ctx context.Context, ownerID models.UserID, page, limit uint64) (*secrets.Page[models.Secret], error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPage", ctx, ownerID, page, limit)
	ret0, _ := ret[0].(*secrets.Page[models.Secret])
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetPage indicates an expected call of GetPage.
func (mr *MockRepositoryMockRecorder) GetPage(ctx, ownerID, page, limit any) *MockRepositoryGetPageCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPage", reflect.TypeOf((*MockRepository)(nil).GetPage), ctx, ownerID, page, limit)
	return &MockRepositoryGetPageCall{Call: call}
}

// MockRepositoryGetPageCall wrap *gomock.Call
type MockRepositoryGetPageCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRepositoryGetPageCall) Return(arg0 *secrets.Page[models.Secret], arg1 error) *MockRepositoryGetPageCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRepositoryGetPageCall) Do(f func(context.Context, models.UserID, uint64, uint64) (*secrets.Page[models.Secret], error)) *MockRepositoryGetPageCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRepositoryGetPageCall) DoAndReturn(f func(context.Context, models.UserID, uint64, uint64) (*secrets.Page[models.Secret], error)) *MockRepositoryGetPageCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Update mocks base method.
func (m *MockRepository) Update(ctx context.Context, id models.SecretID, data *models.Secret) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Update", ctx, id, data)
	ret0, _ := ret[0].(error)
	return ret0
}

// Update indicates an expected call of Update.
func (mr *MockRepositoryMockRecorder) Update(ctx, id, data any) *MockRepositoryUpdateCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Update", reflect.TypeOf((*MockRepository)(nil).Update), ctx, id, data)
	return &MockRepositoryUpdateCall{Call: call}
}

// MockRepositoryUpdateCall wrap *gomock.Call
type MockRepositoryUpdateCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockRepositoryUpdateCall) Return(arg0 error) *MockRepositoryUpdateCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockRepositoryUpdateCall) Do(f func(context.Context, models.SecretID, *models.Secret) error) *MockRepositoryUpdateCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockRepositoryUpdateCall) DoAndReturn(f func(context.Context, models.SecretID, *models.Secret) error) *MockRepositoryUpdateCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
