// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service_test

import (
	"fmt"
	"net/http"
	"strings"
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

	result := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, &result); !ok {
		t.Fatal(message)
	}

	result = us.AuthenticateUser(result.Body, testPassword)
	if ok, message := checkAuthenticationResult(testUser, &testRoles, &result); !ok {
		t.Fatal(message)
	}

	result = us.AuthenticateUser(testUser, altPassword)
	if ok, message := checkError(result.ErrorStatus, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	result = us.AuthenticateUser(altUser, testPassword)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}
}

func TestRegisterUserWrongData(t *testing.T) {
	us := initializeTesteeUserService(t)

	result := us.RegisterUser("", testPassword, &testRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser("str@ngeUser", testPassword, &testRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser("\tsomething", testPassword, &testRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser("some thing", testPassword, &testRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser(testUser, "", &testRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser(testUser, "\tstrange", &testRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser(testUser, testPassword, nil)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser(testUser, testPassword, &[]string{""})
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser(testUser, testPassword, &[]string{" somerole"})
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser(testUser, testPassword, &[]string{"some role"})
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser(testUser, testPassword, &[]string{"role_admin"})
	if ok, message := checkError(result.ErrorStatus, http.StatusForbidden); !ok {
		t.Fatal(message)
	}
}

func TestAuthenticationWrongDate(t *testing.T) {
	us := initializeTesteeUserService(t)

	result := us.AuthenticateUser("", testPassword)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.AuthenticateUser("str@ngeUser", testPassword)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.AuthenticateUser("\tsomething", testPassword)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.AuthenticateUser("some thing", testPassword)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.AuthenticateUser(testUser, "")
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.AuthenticateUser(testUser, "\tstrange")
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}
}

func TestRegisterMultipleUsers(t *testing.T) {
	us := initializeTesteeUserService(t)

	result := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, &result); !ok {
		t.Fatal(message)
	}
	username := result.Body

	result = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, &result); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser(testUser, altPassword, &altRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.AuthenticateUser(username, testPassword)
	if ok, message := checkUnexpectedError(result.ErrorStatus); !ok {
		t.Fatal(message)
	}
}

func TestChangePassword(t *testing.T) {
	us := initializeTesteeUserService(t)

	result := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, &result); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, &result); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword(testUser, "ChangedPW", testUser)
	if ok, message := checkUsernameResult(testUser, &result); !ok {
		t.Fatal(message)
	}

	result = us.AuthenticateUser(testUser, "ChangedPW")
	if ok, message := checkUnexpectedError(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword(testUser, "AnotherChanged", adminUser)
	if ok, message := checkUsernameResult(testUser, &result); !ok {
		t.Fatal(message)
	}

	result = us.AuthenticateUser(testUser, "AnotherChanged")
	if ok, message := checkUnexpectedError(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword(testUser, "Yacp", altUser)
	if ok, message := checkError(result.ErrorStatus, http.StatusForbidden); !ok {
		t.Fatal(message)
	}

	result = us.AuthenticateUser(testUser, "AnotherChanged")
	if ok, message := checkUnexpectedError(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword(testUser, "yacp", "unknown")
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.AuthenticateUser(testUser, "AnotherChanged")
	if ok, message := checkUnexpectedError(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword("unknown", "yacp", adminUser)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}
}

func TestChangePasswordWrongData(t *testing.T) {
	us := initializeTesteeUserService(t)

	result := us.ChangePassword("", testPassword, adminUser)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword("str@ngeUser", testPassword, adminUser)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword("\tsomething", testPassword, adminUser)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword("some thing", testPassword, adminUser)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword(testUser, "", adminUser)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword(testUser, "\tstrange", adminUser)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword(testUser, testPassword, "")
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword(testUser, testPassword, "str@ngeUser")
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword(testUser, testPassword, "\tsomething")
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangePassword(testUser, testPassword, "some thing")
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}
}

func TestChangeRoles(t *testing.T) {
	us := initializeTesteeUserService(t)

	result := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, &result); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, &result); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, testUser, &altRoles, &[]string{testRoles[1], testRoles[2]})
	if ok, message := checkUsernameResult(testUser, &result); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &[]string{testRoles[0], altRoles[0], altRoles[1]}, &us); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, adminUser, &[]string{testRoles[1], testRoles[2]}, &altRoles)
	if ok, message := checkUsernameResult(testUser, &result); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &testRoles, &us); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, altUser, &altRoles, &[]string{})
	if ok, message := checkError(result.ErrorStatus, http.StatusForbidden); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &testRoles, &us); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, "unknown", &altRoles, &[]string{testRoles[1], testRoles[2]})
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &testRoles, &us); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles("unknown", adminUser, &altRoles, &[]string{testRoles[1], testRoles[2]})
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, adminUser, &[]string{}, &[]string{testRoles[0], testRoles[1], testRoles[2]})
	if ok, message := checkUsernameResult(testUser, &result); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &[]string{}, &us); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, testUser, &adminRoles, &[]string{})
	if ok, message := checkError(result.ErrorStatus, http.StatusForbidden); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, adminUser, &adminRoles, &[]string{})
	if ok, message := checkUsernameResult(testUser, &result); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &[]string{adminRoles[0]}, &us); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, adminUser, &[]string{service.AdminRole}, &[]string{})
	if ok, message := checkUsernameResult(testUser, &result); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &[]string{service.AdminRole, adminRoles[0]}, &us); !ok {
		t.Fatal(message)
	}
}

func TestChangeRolesWrongData(t *testing.T) {
	us := initializeTesteeUserService(t)

	result := us.ChangeRoles("", adminUser, &testRoles, &altRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles("str@ngeUser", adminUser, &testRoles, &altRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles("\tsomething", adminUser, &testRoles, &altRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles("some thing", adminUser, &testRoles, &altRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, "", &testRoles, &altRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, "str@ngeUser", &testRoles, &altRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, "\tsomething", &testRoles, &altRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, "some thing", &testRoles, &altRoles)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, testPassword, nil, &[]string{})
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, testPassword, &[]string{""}, &[]string{})
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, testPassword, &[]string{" somerole"}, &[]string{})
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, testPassword, &[]string{"some role"}, &[]string{})
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, testPassword, &[]string{}, nil)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, testPassword, &[]string{}, &[]string{""})
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, testPassword, &[]string{}, &[]string{" somerole"})
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(testUser, testPassword, &[]string{}, &[]string{"some role"})
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}
}

func TestDeleteUser(t *testing.T) {
	us := initializeTesteeUserService(t)

	result := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, &result); !ok {
		t.Fatal(message)
	}

	result = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, &result); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser(testUser, testUser)
	if ok, message := checkError(result.ErrorStatus, http.StatusForbidden); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser(testUser, altUser)
	if ok, message := checkError(result.ErrorStatus, http.StatusForbidden); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser(testUser, "unknown")
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser("unknown", adminUser)
	if ok, message := checkUnexpectedError(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.ChangeRoles(altUser, adminUser, &[]string{"user_admin"}, &[]string{})
	if ok, message := checkUsernameResult(altUser, &result); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser(testUser, adminUser)
	if ok, message := checkUnexpectedError(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser(altUser, adminUser)
	if ok, message := checkUnexpectedError(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser(adminUser, adminUser)
	if ok, message := checkMissingError(result.ErrorStatus); !ok {
		t.Fatal(message)
	}
}

func TestDeleteUserWrongData(t *testing.T) {
	us := initializeTesteeUserService(t)

	result := us.DeleteUser("", adminUser)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser("str@ngeUser", adminUser)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser("\tsomething", adminUser)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser("some thing", adminUser)
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser(testUser, "")
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser(testUser, "str@ngeUser")
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser(testUser, "\tsomething")
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}

	result = us.DeleteUser(testUser, "some thing")
	if ok, message := checkWrongData(result.ErrorStatus); !ok {
		t.Fatal(message)
	}
}

func checkRolesForUserPW(expected string, password string, expectedRoles *[]string, us *service.UserService) (bool, string) {
	result := us.AuthenticateUser(expected, password)
	return checkAuthenticationResult(expected, expectedRoles, &result)
}

func checkUsernameResult(expected string, result *service.RequestResult) (bool, string) {
	if result.ErrorStatus != nil {
		return false, unexpectedError(result.ErrorStatus)
	}
	if result.Body != expected {
		return false, stringMismatch(expected, result.Body)
	}
	return true, ""
}

func checkAuthenticationResult(expectedName string, expectedRoles *[]string, result *service.RequestResult) (bool, string) {
	if result.ErrorStatus != nil {
		return false, unexpectedError(result.ErrorStatus)
	}

	username, roles, err := libs.ParseToken(result.Body)
	if err != nil {
		return false, unexpectedError(result.ErrorStatus)
	}
	if username != expectedName {
		return false, stringMismatch(expectedName, username)
	}
	if !libs.Contains(expectedRoles, service.AdminRole) {
		extendExpected := append(*expectedRoles, service.UserRole)
		expectedRoles = &extendExpected
	}
	return libs.TwoStringListsHaveSameContent(expectedRoles, roles), roleMismatch(expectedRoles, roles)
}

func checkWrongData(err *libs.RestError) (bool, string) {
	return checkError(err, http.StatusBadRequest)
}

func checkError(err *libs.RestError, expected int) (bool, string) {
	if ok, message := checkMissingError(err); !ok {
		return ok, message
	}
	return errorCodeMatch(expected, err)
}

func checkMissingError(err *libs.RestError) (bool, string) {
	if err == nil {
		return false, missingError
	}
	return true, ""
}

func errorCodeMatch(expected int, found *libs.RestError) (bool, string) {
	if found.ErrorCode == expected {
		return true, ""
	} else {
		return false, fmt.Sprintf("Value mismatch: expected: %d, found: %d", expected, found.ErrorCode)
	}
}

func roleMismatch(expected *[]string, found *[]string) string {
	return stringMismatch(strings.Join(*expected, ";"), strings.Join(*found, ";"))
}

func stringMismatch(expected string, found string) string {
	return fmt.Sprintf("Value mismatch: expected: %s, found: %s", expected, found)
}

func checkUnexpectedError(err *libs.RestError) (bool, string) {
	if err != nil {
		return false, unexpectedError(err)
	}
	return true, ""
}

const missingError = "Error expected at this point"

func unexpectedError(err *libs.RestError) string {
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
