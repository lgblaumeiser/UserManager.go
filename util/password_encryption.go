// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package util

import (
	"golang.org/x/crypto/bcrypt"
)

const cryptCost = 12

func EncryptPassword(password string) (string, *RestError) {
	if !IsCleanString(password) {
		return "", IllegalArgument("password")
	}
	encryptedPW, err := bcrypt.GenerateFromPassword([]byte(password), cryptCost)
	if err != nil {
		return "", UnexpectedBehavior(&err)
	}

	return string(encryptedPW), nil
}

func CheckPassword(encrypted string, given string) *RestError {
	err := bcrypt.CompareHashAndPassword([]byte(encrypted), []byte(given))
	if err != nil {
		return UnauthorizedUserError(&err)
	}
	return nil
}
