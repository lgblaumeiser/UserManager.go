// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service

import "encoding/json"

type User struct {
	Username string `json:"username"`

	Password string `json:"password"`

	Roles *[]string `json:"roles"`
}

func EncodeUser(user *User) ([]byte, error) {
	return json.Marshal(user)
}

func DecodeUser(data []byte) (*User, error) {
	user := User{}
	err := json.Unmarshal(data, &user)
	return &user, err
}
