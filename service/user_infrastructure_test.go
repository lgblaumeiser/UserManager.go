// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service_test

import "testing"

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

	_, err = us.AuthenticateUser(testUser, testPassword)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser(altUser, altPassword)
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

	err = us.Restore(adminUser, zipData)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatalf(message)
	}

	expectedRoles := append(testRoles, altRoles...)
	result, err = us.AuthenticateUser(testUser, altPassword)
	if ok, message := checkAuthenticationResult(testUser, &expectedRoles, result, err); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser(altUser, altPassword)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}
}
