package service

type UserStore interface {
	StoreUser(user *User) (string, error)
	GetUser(username string) *User
	DeleteUser(user *User) error
}
