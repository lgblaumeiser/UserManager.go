// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/lgblaumeiser/usermanager/util"

	"github.com/google/uuid"
	"github.com/lgblaumeiser/usermanager/service"
	"github.com/lgblaumeiser/usermanager/store"
)

func checkRolesForUserPW(expected string, password string, expectedRoles *[]string, us *service.UserService) (bool, string) {
	result, err := us.AuthenticateUser(expected, password)
	return checkAuthenticationResult(expected, expectedRoles, result, err)
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

func checkAuthenticationResult(expectedName string, expectedRoles *[]string, result string, rerr *util.RestError) (bool, string) {
	if rerr != nil {
		return false, unexpectedError(rerr)
	}

	username, roles, err := util.ParseToken(result)
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
	return util.TwoStringListsHaveSameContent(expectedRoles, roles), roleMismatch(expectedRoles, roles)
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

func initializeTesteeUserService(t *testing.T) service.UserService {
	key, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("Cannot create key: %s", err.Error())
	}
	util.InitializeJwtService([]byte(key.String()))

	store := store.CreateMemoryStore()
	return service.NewUserService(store)
}
