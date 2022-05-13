// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service

type UserStore interface {
	StoreUser(user *User) (string, error)
	GetUser(username string) *User
	DeleteUser(user *User) error
}
