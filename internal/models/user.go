package models

type (
	UserID         string
	HashedPassword []byte
)

type User struct {
	ID        UserID
	Login     string
	Pwd       HashedPassword
	MasterPwd HashedPassword
}

func NewUser(login string, pwd, masterPwd HashedPassword) *User {
	return &User{
		Login:     login,
		Pwd:       pwd,
		MasterPwd: masterPwd,
	}
}
