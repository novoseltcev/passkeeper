// Code generated by MockGen. DO NOT EDIT.
// Source: service.go
//
// Generated by this command:
//
//	mockgen -destination=./mocks/service_mocks.go -package=mocks -source=service.go -typed
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	models "github.com/novoseltcev/passkeeper/internal/models"
	gomock "go.uber.org/mock/gomock"
)

// MockService is a mock of Service interface.
type MockService struct {
	ctrl     *gomock.Controller
	recorder *MockServiceMockRecorder
	isgomock struct{}
}

// MockServiceMockRecorder is the mock recorder for MockService.
type MockServiceMockRecorder struct {
	mock *MockService
}

// NewMockService creates a new mock instance.
func NewMockService(ctrl *gomock.Controller) *MockService {
	mock := &MockService{ctrl: ctrl}
	mock.recorder = &MockServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockService) EXPECT() *MockServiceMockRecorder {
	return m.recorder
}

// Login mocks base method.
func (m *MockService) Login(ctx context.Context, login, password string) (models.UserID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Login", ctx, login, password)
	ret0, _ := ret[0].(models.UserID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Login indicates an expected call of Login.
func (mr *MockServiceMockRecorder) Login(ctx, login, password any) *MockServiceLoginCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Login", reflect.TypeOf((*MockService)(nil).Login), ctx, login, password)
	return &MockServiceLoginCall{Call: call}
}

// MockServiceLoginCall wrap *gomock.Call
type MockServiceLoginCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockServiceLoginCall) Return(arg0 models.UserID, arg1 error) *MockServiceLoginCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockServiceLoginCall) Do(f func(context.Context, string, string) (models.UserID, error)) *MockServiceLoginCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockServiceLoginCall) DoAndReturn(f func(context.Context, string, string) (models.UserID, error)) *MockServiceLoginCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Register mocks base method.
func (m *MockService) Register(ctx context.Context, login, password, passphrase string) (models.UserID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Register", ctx, login, password, passphrase)
	ret0, _ := ret[0].(models.UserID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Register indicates an expected call of Register.
func (mr *MockServiceMockRecorder) Register(ctx, login, password, passphrase any) *MockServiceRegisterCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Register", reflect.TypeOf((*MockService)(nil).Register), ctx, login, password, passphrase)
	return &MockServiceRegisterCall{Call: call}
}

// MockServiceRegisterCall wrap *gomock.Call
type MockServiceRegisterCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockServiceRegisterCall) Return(arg0 models.UserID, arg1 error) *MockServiceRegisterCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockServiceRegisterCall) Do(f func(context.Context, string, string, string) (models.UserID, error)) *MockServiceRegisterCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockServiceRegisterCall) DoAndReturn(f func(context.Context, string, string, string) (models.UserID, error)) *MockServiceRegisterCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// VerifyPassphrase mocks base method.
func (m *MockService) VerifyPassphrase(ctx context.Context, ownerID models.UserID, passphrase string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyPassphrase", ctx, ownerID, passphrase)
	ret0, _ := ret[0].(error)
	return ret0
}

// VerifyPassphrase indicates an expected call of VerifyPassphrase.
func (mr *MockServiceMockRecorder) VerifyPassphrase(ctx, ownerID, passphrase any) *MockServiceVerifyPassphraseCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyPassphrase", reflect.TypeOf((*MockService)(nil).VerifyPassphrase), ctx, ownerID, passphrase)
	return &MockServiceVerifyPassphraseCall{Call: call}
}

// MockServiceVerifyPassphraseCall wrap *gomock.Call
type MockServiceVerifyPassphraseCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockServiceVerifyPassphraseCall) Return(arg0 error) *MockServiceVerifyPassphraseCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockServiceVerifyPassphraseCall) Do(f func(context.Context, models.UserID, string) error) *MockServiceVerifyPassphraseCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockServiceVerifyPassphraseCall) DoAndReturn(f func(context.Context, models.UserID, string) error) *MockServiceVerifyPassphraseCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// MockHasher is a mock of Hasher interface.
type MockHasher struct {
	ctrl     *gomock.Controller
	recorder *MockHasherMockRecorder
	isgomock struct{}
}

// MockHasherMockRecorder is the mock recorder for MockHasher.
type MockHasherMockRecorder struct {
	mock *MockHasher
}

// NewMockHasher creates a new mock instance.
func NewMockHasher(ctrl *gomock.Controller) *MockHasher {
	mock := &MockHasher{ctrl: ctrl}
	mock.recorder = &MockHasherMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockHasher) EXPECT() *MockHasherMockRecorder {
	return m.recorder
}

// Compare mocks base method.
func (m *MockHasher) Compare(hash, v string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Compare", hash, v)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Compare indicates an expected call of Compare.
func (mr *MockHasherMockRecorder) Compare(hash, v any) *MockHasherCompareCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Compare", reflect.TypeOf((*MockHasher)(nil).Compare), hash, v)
	return &MockHasherCompareCall{Call: call}
}

// MockHasherCompareCall wrap *gomock.Call
type MockHasherCompareCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockHasherCompareCall) Return(arg0 bool, arg1 error) *MockHasherCompareCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockHasherCompareCall) Do(f func(string, string) (bool, error)) *MockHasherCompareCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockHasherCompareCall) DoAndReturn(f func(string, string) (bool, error)) *MockHasherCompareCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Generate mocks base method.
func (m *MockHasher) Generate(v string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Generate", v)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Generate indicates an expected call of Generate.
func (mr *MockHasherMockRecorder) Generate(v any) *MockHasherGenerateCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Generate", reflect.TypeOf((*MockHasher)(nil).Generate), v)
	return &MockHasherGenerateCall{Call: call}
}

// MockHasherGenerateCall wrap *gomock.Call
type MockHasherGenerateCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *MockHasherGenerateCall) Return(arg0 string, arg1 error) *MockHasherGenerateCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *MockHasherGenerateCall) Do(f func(string) (string, error)) *MockHasherGenerateCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *MockHasherGenerateCall) DoAndReturn(f func(string) (string, error)) *MockHasherGenerateCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
