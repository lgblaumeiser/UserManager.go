// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package functions

import (
	"net/http"
	"testing"
)

const testPassword = "My c00l Te$tpassword"

func TestCleanPasswordEncryption(t *testing.T) {
	encryptedPassword, err := EncryptPassword(testPassword)
	if err != nil {
		t.Errorf("Error while encrypting password: %s", err.Error())
	}

	err = CheckPassword(encryptedPassword, testPassword)
	if err != nil {
		t.Errorf("Check of password failed: %s", err.Error())
	}
}

func TestPasswordCheckShouldFailForWrongPassword(t *testing.T) {
	encryptedPassword, err := EncryptPassword(testPassword)
	if err != nil {
		t.Errorf("Error while encrypting password: %s", err.Error())
	}

	err = CheckPassword(encryptedPassword, "Some other stuff")
	if err == nil {
		t.Errorf("The check of a password that does not match the encrypted must fail")
	}
	if (*err).ErrorCode != http.StatusUnauthorized {
		t.Errorf("Wrong error code, should be %d, is %d", http.StatusUnauthorized, (*err).ErrorCode)
	}
}

func TestEmptyPasswordShouldFail(t *testing.T) {
	_, err := EncryptPassword("")
	if err == nil {
		t.Errorf("Empty password should fail")
	}
	if (*err).ErrorCode != http.StatusBadRequest {
		t.Errorf("Wrong error code, should be %d, is %d", http.StatusBadRequest, (*err).ErrorCode)
	}
}
