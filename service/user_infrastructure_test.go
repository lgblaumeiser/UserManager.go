// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service_test

import (
	"net/http"
	"testing"

	"github.com/lgblaumeiser/usermanager/service"
)

func TestBackupAndRestore(t *testing.T) {
	us := initializeTesteeUserService(t)

	result, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	result, err = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, result, err); !ok {
		t.Fatal(message)
	}

	zipData, err := us.Backup(adminUser)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatalf(message)
	}

	us = initializeTesteeUserService(t)

	err = us.Restore(adminUser, zipData)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatalf(message)
	}

	_, _, err = us.AuthenticateUser(testUser, testPassword)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser(altUser, altPassword)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}
}

func TestBackupAndRestoreExistingUser(t *testing.T) {
	us := initializeTesteeUserService(t)

	result, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	result, err = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, result, err); !ok {
		t.Fatal(message)
	}

	zipData, err := us.Backup(adminUser)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatalf(message)
	}

	us = initializeTesteeUserService(t)

	result, err = us.RegisterUser(testUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	result, err = us.RegisterUser(thirdUser, thirdPassword, &altRoles)
	if ok, message := checkUsernameResult(thirdUser, result, err); !ok {
		t.Fatal(message)
	}

	result, err = us.ChangePassword(adminUser, testPassword, adminUser)
	if ok, message := checkUsernameResult(adminUser, result, err); !ok {
		t.Fatal(message)
	}

	err = us.Restore(adminUser, zipData)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatalf(message)
	}

	access, refresh, err := us.AuthenticateUser(testUser, testPassword)
	if ok, message := checkAuthenticationResult(testUser, &testRoles, access, refresh, err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser(testUser, altPassword)
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	access, refresh, err = us.AuthenticateUser(adminUser, adminPassword)
	if ok, message := checkAuthenticationResult(adminUser, &[]string{service.AdminRole}, access, refresh, err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser(adminUser, testPassword)
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	access, refresh, err = us.AuthenticateUser(altUser, altPassword)
	if ok, message := checkAuthenticationResult(altUser, &altRoles, access, refresh, err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser(thirdUser, thirdPassword)
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}
}

func TestBackupAndRestoreWrongData(t *testing.T) {
	us := initializeTesteeUserService(t)

	result, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	_, err = us.Backup("  any")
	if ok, message := checkWrongData(err); !ok {
		t.Error(message)
	}

	_, err = us.Backup(testUser)
	if ok, message := checkError(err, http.StatusForbidden); !ok {
		t.Error(message)
	}

	data, err := us.Backup(adminUser)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatalf(message)
	}

	us = initializeTesteeUserService(t)

	err = us.Restore("  any", data)
	if ok, message := checkWrongData(err); !ok {
		t.Error(message)
	}

	err = us.Restore(testUser, data)
	if ok, message := checkError(err, http.StatusForbidden); !ok {
		t.Error(message)
	}

	result, err = us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	err = us.Restore(testUser, data)
	if ok, message := checkError(err, http.StatusForbidden); !ok {
		t.Error(message)
	}
}
