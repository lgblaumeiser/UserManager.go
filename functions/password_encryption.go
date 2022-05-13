package functions

import (
	crypt "golang.org/x/crypto/bcrypt"
)

const cryptCost = 16

func EncryptPassword(password string) (string, error) {
	if !IsCleanString(password) {
		return "", IllegalArgument("given password string is empty or has surrounding whitespaces")
	}
	encryptedPW, err := crypt.GenerateFromPassword([]byte(password), cryptCost)
	if err != nil {
		return "", UnexpectedBehaviorError(err)
	}

	return string(encryptedPW), nil
}

func CheckPassword(encrypted string, given string) error {
	err := crypt.CompareHashAndPassword([]byte(encrypted), []byte(given))
	if err != nil {
		return UnauthorizedUserError(err)
	}
	return nil
}
