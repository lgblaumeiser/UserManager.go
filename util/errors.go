// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package util

import (
	"fmt"
	"net/http"
)

const tokenExpired = "token expired"
const unexpectedBehavior = "unexpected behavior"
const authenicationFailed = "user or password incorrect"
const noSufficientRights = "no sufficient rights required for this action"
const illegalData = "given argument is not according to spec: "

type RestError struct {
	ErrorCode    int
	Message      string
	WrappedError *error
}

func (e *RestError) Error() string {
	return fmt.Sprintf("%d: %s", e.ErrorCode, e.Message)
}

func TokenExpired() *RestError {
	return createError(http.StatusUnauthorized, tokenExpired)
}
func UnexpectedBehavior(message *error) *RestError {
	return createErrorWithWrapped(http.StatusInternalServerError, unexpectedBehavior, message)
}

func UnauthorizedUserError(message *error) *RestError {
	return createErrorWithWrapped(http.StatusUnauthorized, authenicationFailed, message)
}

func UnauthorizedUser() *RestError {
	return createError(http.StatusUnauthorized, authenicationFailed)
}

func MissingAdminRights() *RestError {
	return createError(http.StatusForbidden, noSufficientRights)
}

func IllegalArgument(message string) *RestError {
	return createError(http.StatusBadRequest, illegalData+message)
}

func createErrorWithWrapped(code int, message string, wrapped *error) *RestError {
	if code != http.StatusBadRequest && code != http.StatusUnauthorized && code != http.StatusForbidden {
		code = http.StatusInternalServerError
	}
	newError := RestError{code, message, wrapped}
	return &newError
}

func createError(code int, message string) *RestError {
	return createErrorWithWrapped(code, message, nil)
}
