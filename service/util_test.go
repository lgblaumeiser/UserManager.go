// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service_test

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/lgblaumeiser/usermanager/service"
	"github.com/lgblaumeiser/usermanager/util"
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

var thirdUser = "thirdUser"
var thirdPassword = "my password"

var uninteresting = "Uninteresting String"

func checkRolesForUserPW(expected string, password string, expectedRoles *[]string, us *service.UserService) (bool, string) {
	access, refresh, err := us.AuthenticateUser(expected, password)
	return checkAuthenticationResult(expected, expectedRoles, access, refresh, err)
}

func checkUsernameResult(expected string, result string, rerr *util.RestError) (bool, string) {
	if rerr != nil {
		return false, unexpectedError(rerr)
	}
	if result != expected {
		return false, stringMismatch(expected, result)
	}
	return true, ""
}

func checkAuthenticationResult(expectedName string, expectedRoles *[]string, access string, refresh string, rerr *util.RestError) (bool, string) {
	if rerr != nil {
		return false, unexpectedError(rerr)
	}

	username, roles, _, err := util.ParseToken(access)
	if err != nil {
		return false, unexpectedError(rerr)
	}
	if username != expectedName {
		return false, stringMismatch(expectedName, username)
	}
	if !util.Contains(expectedRoles, service.AdminRole) {
		extendExpected := append(*expectedRoles, service.UserRole)
		expectedRoles = &extendExpected
	}
	if !util.TwoStringListsHaveSameContent(expectedRoles, roles) {
		return false, roleMismatch(expectedRoles, roles)
	}

	username, roles, _, err = util.ParseToken(refresh)
	if err != nil {
		return false, unexpectedError(rerr)
	}
	if username != expectedName {
		return false, stringMismatch(expectedName, username)
	}
	if roles != nil {
		return false, "nil expected for roles result"
	}

	return true, ""
}

func checkWrongData(err *util.RestError) (bool, string) {
	return checkError(err, http.StatusBadRequest)
}

func checkError(err *util.RestError, expected int) (bool, string) {
	if ok, message := checkMissingError(err); !ok {
		return ok, message
	}
	return errorCodeMatch(expected, err)
}

func checkMissingError(err *util.RestError) (bool, string) {
	if err == nil {
		return false, missingError
	}
	return true, ""
}

func errorCodeMatch(expected int, found *util.RestError) (bool, string) {
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

func checkUnexpectedError(err *util.RestError) (bool, string) {
	if err != nil {
		return false, unexpectedError(err)
	}
	return true, ""
}

const missingError = "Error expected at this point"

func unexpectedError(err *util.RestError) string {
	return fmt.Sprintf("Unexpected error: %s", err.Error())
}
