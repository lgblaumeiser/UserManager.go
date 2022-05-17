// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package store

import (
	service "github.com/lgblaumeiser/usermanager/service"
)

type MemoryStore struct {
	userMap map[string]*service.User
}

func CreateMemoryStore() *MemoryStore {
	store := MemoryStore{userMap: map[string]*service.User{}}
	return &store
}

func (m *MemoryStore) AddUser(user *service.User) (string, bool, error) {
	if _, ok := m.userMap[user.Username]; ok {
		return "", false, nil
	}
	m.userMap[user.Username] = user
	return user.Username, true, nil
}

func (m *MemoryStore) StoreUser(user *service.User) (string, error) {
	m.userMap[user.Username] = user
	return user.Username, nil
}

func (m *MemoryStore) GetUser(username string) *service.User {
	user, ok := m.userMap[username]
	if !ok {
		return nil
	}
	return user
}

func (m *MemoryStore) DeleteUser(user *service.User) error {
	delete(m.userMap, user.Username)
	return nil
}

func (m *MemoryStore) GetUsers() *[]service.User {
	users := []service.User{}
	for _, user := range m.userMap {
		users = append(users, *user)
	}
	return &users
}
