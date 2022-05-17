// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package functions

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

const testOverall = "Test String"
const testDetails = "Test Details"

var wrapped = errors.New(testDetails)

func TestErrorCreationMessage(t *testing.T) {
	err := createError(http.StatusBadRequest, testOverall)
	checkError(t, err, http.StatusBadRequest, testOverall)
}

func TestErrorCreation(t *testing.T) {
	err := createErrorWithWrapped(http.StatusUnauthorized, testOverall, &wrapped)
	checkErrorWithWrapped(t, err, http.StatusUnauthorized, testOverall, &wrapped)
}

func TestUnexpectedBehaviorError(t *testing.T) {
	err := UnexpectedBehavior(&wrapped)
	checkErrorWithWrapped(t, err, http.StatusInternalServerError, unexpectedBehavior, &wrapped)
}

func TestTokenExpired(t *testing.T) {
	err := TokenExpired()
	checkError(t, err, http.StatusUnauthorized, tokenExpired)
}

func TestUnauthorizedUserError(t *testing.T) {
	err := UnauthorizedUserError(&wrapped)
	checkErrorWithWrapped(t, err, http.StatusUnauthorized, authenicationFailed, &wrapped)
}

func TestUnauthorizedUser(t *testing.T) {
	err := UnauthorizedUser()
	checkError(t, err, http.StatusUnauthorized, authenicationFailed)
}

func TestMissingAdminRights(t *testing.T) {
	err := MissingAdminRights()
	checkError(t, err, http.StatusForbidden, noSufficientRights)
}

func TestIllegalArgument(t *testing.T) {
	err := IllegalArgument(testDetails)
	checkError(t, err, http.StatusBadRequest, illegalData+testDetails)
}

func TestWithWrongCode(t *testing.T) {
	err := createError(-1, testDetails)
	checkError(t, err, http.StatusInternalServerError, testDetails)
}

func checkError(t *testing.T, err *RestError, code int, message string) {
	if code != err.ErrorCode {
		t.Errorf("Wrong code: %d, should be %d", err.ErrorCode, code)
	}
	if message != err.Message {
		t.Errorf("Wrong message: '%s', should be '%s'", err.Message, message)
	}
	if !strings.Contains(err.Error(), message) {
		t.Errorf("Error message should contain given error description")
	}
	if !strings.Contains(err.Error(), strconv.Itoa(code)) {
		t.Errorf("Error message should contain given error code")
	}
}

func checkErrorWithWrapped(t *testing.T, err *RestError, code int, message string, wrapped *error) {
	checkError(t, err, code, message)
	if (*wrapped).Error() != (*err.WrappedError).Error() {
		t.Errorf("Wrong error message: %s", err.Error())
	}
}
