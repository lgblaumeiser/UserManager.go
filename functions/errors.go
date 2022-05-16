// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package functions

import (
	"fmt"
)

const BadRequest = 400
const Unauthorized = 401
const Forbidden = 403
const InternalServerError = 500

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
	return createError(Unauthorized, tokenExpired)
}
func UnexpectedBehavior(message *error) *RestError {
	return createErrorWithWrapped(InternalServerError, unexpectedBehavior, message)
}

func UnauthorizedUserError(message *error) *RestError {
	return createErrorWithWrapped(Unauthorized, authenicationFailed, message)
}

func UnauthorizedUser() *RestError {
	return createError(Unauthorized, authenicationFailed)
}

func MissingAdminRights() *RestError {
	return createError(Forbidden, noSufficientRights)
}

func IllegalArgument(message string) *RestError {
	return createError(BadRequest, illegalData+message)
}

func createErrorWithWrapped(code int, message string, wrapped *error) *RestError {
	if code != BadRequest && code != Unauthorized && code != Forbidden {
		code = InternalServerError
	}
	newError := RestError{code, message, wrapped}
	return &newError
}

func createError(code int, message string) *RestError {
	return createErrorWithWrapped(code, message, nil)
}
