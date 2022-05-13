// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service_test

import (
	"fmt"
	"testing"

	uuid "github.com/google/uuid"
	libs "github.com/lgblaumeiser/usermanager/functions"
	service "github.com/lgblaumeiser/usermanager/service"
	store "github.com/lgblaumeiser/usermanager/store"
)

var testUser = "testUser"
var testPassword = "super password"
var testRoles = []string{"role_1", "role_2", "role_3"}

var altUser = "altUser"
var altPassword = "b@d pw"
var altRoles = []string{"alt_role_1", "alt_role_2"}

var adminUser = "admin"
var adminPassword = "admin"
var adminRoles = []string{"user_admin"}

func TestUserAuthentificationService(t *testing.T) {
	us := initializeTesteeUserService(t)

	username, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, username, err); !ok {
		t.Fatal(message)
	}

	token, err := us.AuthenticateUser(username, testPassword)
	if ok, message := checkAuthenticationResult(testUser, &testRoles, token, err); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser(testUser, altPassword)
	if ok, message := checkError(err, libs.Unauthorized); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser(altUser, testPassword)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}
}

func TestRegisterUserWrongData(t *testing.T) {
	us := initializeTesteeUserService(t)

	_, err := us.RegisterUser("", testPassword, &testRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.RegisterUser("str@ngeUser", testPassword, &testRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.RegisterUser("\tsomething", testPassword, &testRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.RegisterUser("some thing", testPassword, &testRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.RegisterUser(testUser, "", &testRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.RegisterUser(testUser, "\tstrange", &testRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.RegisterUser(testUser, testPassword, nil)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.RegisterUser(testUser, testPassword, &[]string{})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.RegisterUser(testUser, testPassword, &[]string{""})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.RegisterUser(testUser, testPassword, &[]string{" somerole"})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.RegisterUser(testUser, testPassword, &[]string{"some role"})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.RegisterUser(testUser, testPassword, &[]string{"role_admin"})
	if ok, message := checkError(err, libs.Forbidden); !ok {
		t.Fatal(message)
	}
}

func TestAuthenticationWrongDate(t *testing.T) {
	us := initializeTesteeUserService(t)

	_, err := us.AuthenticateUser("", testPassword)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser("str@ngeUser", testPassword)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser("\tsomething", testPassword)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser("some thing", testPassword)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser(testUser, "")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser(testUser, "\tstrange")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}
}

func TestRegisterMultipleUsers(t *testing.T) {
	us := initializeTesteeUserService(t)

	username, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, username, err); !ok {
		t.Fatal(message)
	}

	username2, err := us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, username2, err); !ok {
		t.Fatal(message)
	}

	_, err = us.RegisterUser(testUser, altPassword, &altRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser(username, testPassword)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}
}

func TestChangePassword(t *testing.T) {
	us := initializeTesteeUserService(t)

	username, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, username, err); !ok {
		t.Fatal(message)
	}

	username, err = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, username, err); !ok {
		t.Fatal(message)
	}

	username, err = us.ChangePassword(testUser, "ChangedPW", testUser)
	if ok, message := checkUsernameResult(testUser, username, err); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser(testUser, "ChangedPW")
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}

	username, err = us.ChangePassword(testUser, "AnotherChanged", adminUser)
	if ok, message := checkUsernameResult(testUser, username, err); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser(testUser, "AnotherChanged")
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword(testUser, "Yacp", altUser)
	if ok, message := checkError(err, libs.Forbidden); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser(testUser, "AnotherChanged")
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword(testUser, "yacp", "unknown")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.AuthenticateUser(testUser, "AnotherChanged")
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword("unknown", "yacp", adminUser)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}
}

func TestChangePasswordWrongData(t *testing.T) {
	us := initializeTesteeUserService(t)

	_, err := us.ChangePassword("", testPassword, adminUser)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword("str@ngeUser", testPassword, adminUser)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword("\tsomething", testPassword, adminUser)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword("some thing", testPassword, adminUser)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword(testUser, "", adminUser)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword(testUser, "\tstrange", adminUser)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword(testUser, testPassword, "")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword(testUser, testPassword, "str@ngeUser")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword(testUser, testPassword, "\tsomething")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword(testUser, testPassword, "some thing")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}
}

func TestChangeRoles(t *testing.T) {
	us := initializeTesteeUserService(t)

	username, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, username, err); !ok {
		t.Fatal(message)
	}

	username, err = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, username, err); !ok {
		t.Fatal(message)
	}

	username, err = us.ChangeRoles(testUser, testUser, &altRoles, &[]string{testRoles[1], testRoles[2]})
	if ok, message := checkUsernameResult(testUser, username, err); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &[]string{testRoles[0], altRoles[0], altRoles[1]}, &us); !ok {
		t.Fatal(message)
	}

	username, err = us.ChangeRoles(testUser, adminUser, &[]string{testRoles[1], testRoles[2]}, &altRoles)
	if ok, message := checkUsernameResult(testUser, username, err); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &testRoles, &us); !ok {
		t.Fatal(message)
	}

	username, err = us.ChangeRoles(testUser, adminUser, &[]string{}, &[]string{testRoles[0], testRoles[1], testRoles[2]})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &testRoles, &us); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, altUser, &altRoles, &[]string{testRoles[1], testRoles[2]})
	if ok, message := checkError(err, libs.Forbidden); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &testRoles, &us); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, "unknown", &altRoles, &[]string{testRoles[1], testRoles[2]})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &testRoles, &us); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles("unknown", adminUser, &altRoles, &[]string{testRoles[1], testRoles[2]})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	username, err = us.ChangeRoles(testUser, testUser, &adminRoles, &[]string{})
	if ok, message := checkError(err, libs.Forbidden); !ok {
		t.Fatal(message)
	}

	username, err = us.ChangeRoles(testUser, adminUser, &adminRoles, &[]string{})
	if ok, message := checkUsernameResult(testUser, username, err); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &[]string{testRoles[0], testRoles[1], testRoles[2], adminRoles[0]}, &us); !ok {
		t.Fatal(message)
	}
}

func TestChangeRolesWrongData(t *testing.T) {
	us := initializeTesteeUserService(t)

	_, err := us.ChangeRoles("", adminUser, &testRoles, &altRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles("str@ngeUser", adminUser, &testRoles, &altRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles("\tsomething", adminUser, &testRoles, &altRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles("some thing", adminUser, &testRoles, &altRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, "", &testRoles, &altRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, "str@ngeUser", &testRoles, &altRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, "\tsomething", &testRoles, &altRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, "some thing", &testRoles, &altRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, testPassword, nil, &[]string{})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, testPassword, &[]string{""}, &[]string{})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, testPassword, &[]string{" somerole"}, &[]string{})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, testPassword, &[]string{"some role"}, &[]string{})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, testPassword, &[]string{}, nil)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, testPassword, &[]string{}, &[]string{""})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, testPassword, &[]string{}, &[]string{" somerole"})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, testPassword, &[]string{}, &[]string{"some role"})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}
}

func TestDeleteUser(t *testing.T) {
	us := initializeTesteeUserService(t)

	username, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, username, err); !ok {
		t.Fatal(message)
	}

	username, err = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, username, err); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(testUser, testUser)
	if ok, message := checkError(err, libs.Forbidden); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(testUser, altUser)
	if ok, message := checkError(err, libs.Forbidden); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(testUser, "unknown")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser("unknown", adminUser)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}

	username, err = us.ChangeRoles(altUser, adminUser, &[]string{"user_admin"}, &[]string{})
	if ok, message := checkUsernameResult(altUser, username, err); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(testUser, adminUser)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(altUser, adminUser)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(adminUser, adminUser)
	if ok, message := checkMissingError(err); !ok {
		t.Fatal(message)
	}
}

func TestDeleteUserWrongData(t *testing.T) {
	us := initializeTesteeUserService(t)

	err := us.DeleteUser("", adminUser)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser("str@ngeUser", adminUser)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser("\tsomething", adminUser)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser("some thing", adminUser)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(testUser, "")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(testUser, "str@ngeUser")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(testUser, "\tsomething")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(testUser, "some thing")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}
}

func checkRolesForUserPW(expected string, password string, expectedRoles *[]string, us *service.UserService) (bool, string) {
	token, err := us.AuthenticateUser(expected, password)
	return checkAuthenticationResult(expected, expectedRoles, token, err)
}

func checkUsernameResult(expected string, found string, err error) (bool, string) {
	if err != nil {
		return false, unexpectedError(err)
	}
	if found != expected {
		return false, stringMismatch(expected, found)
	}
	return true, ""
}

func checkAuthenticationResult(expectedName string, expectedRoles *[]string, token string, err error) (bool, string) {
	if err != nil {
		return false, unexpectedError(err)
	}

	username, roles, err := libs.ParseToken(token)
	if err != nil {
		return false, unexpectedError(err)
	}
	if username != expectedName {
		return false, stringMismatch(expectedName, username)
	}
	return rolesUnmatched(expectedRoles, roles)
}

func rolesUnmatched(expected *[]string, found string) (bool, string) {
	roleList := libs.DecodeRoles(found)
	if len(*expected) != len(*roleList) {
		return false, roleMismatch(expected, found)
	}
	for _, outer := range *expected {
		ok := false
		for _, inner := range *roleList {
			if inner == outer {
				ok = true
			}
		}
		if !ok {
			return false, roleMismatch(expected, found)
		}
	}
	return true, ""
}

func checkWrongData(err error) (bool, string) {
	return checkError(err, libs.BadData)
}

func checkError(err error, expected int) (bool, string) {
	if ok, message := checkMissingError(err); !ok {
		return ok, message
	}
	return errorCodeMatch(expected, err)
}

func checkMissingError(err error) (bool, string) {
	if err == nil {
		return false, missingError
	}
	return true, ""
}

func errorCodeMatch(expected int, found error) (bool, string) {
	errorCode := libs.RetrieveErrorCode(found)
	if errorCode == expected {
		return true, ""
	} else {
		return false, fmt.Sprintf("Value mismatch: expected: %d, found: %d", expected, errorCode)
	}
}

func roleMismatch(expected *[]string, found string) string {
	return stringMismatch(libs.EncodeRoles(expected), found)
}

func stringMismatch(expected string, found string) string {
	return fmt.Sprintf("Value mismatch: expected: %s, found: %s", expected, found)
}

func checkUnexpectedError(err error) (bool, string) {
	if err != nil {
		return false, unexpectedError(err)
	}
	return true, ""
}

const missingError = "Error expected at this point"

func unexpectedError(err error) string {
	return fmt.Sprintf("Unexpected error: %s", err.Error())
}

func initializeTesteeUserService(t *testing.T) service.UserService {
	key, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("Cannot create key: %s", err.Error())
	}
	libs.InitializeJwtService([]byte(key.String()))

	store := store.CreateMemoryStore()
	return service.NewUserService(store)
}
