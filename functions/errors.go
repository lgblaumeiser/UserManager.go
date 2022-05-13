// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package functions

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const BadData = 1
const Unexpected = 2
const Unauthorized = 3
const Forbidden = 4

const tokenValidationFailed = "token validation failed"
const tokenExpired = "token expired"
const unexpectedBehavior = "unexpected behavior"
const authenicationFailed = "user or password incorrect"
const missingAdminRights = "admin rights required for this action"
const illegalData = "given argument is not according to spec"

const defaultDetails = "n/a"
const formatString = "%d: %s: %s"

var nonFormatted = errors.New("non-formatted")

func TokenValidationError(message error) error {
	return createError(BadData, tokenValidationFailed, message)
}

func TokenValidation(message string) error {
	return createErrorMsg(BadData, tokenValidationFailed, message)
}

func TokenExpired() error {
	return createErrorMsg(Unauthorized, tokenExpired, defaultDetails)
}
func UnexpectedBehaviorError(message error) error {
	return createError(Unexpected, unexpectedBehavior, message)
}

func UnexpectedBehavior(message string) error {
	return createErrorMsg(Unexpected, unexpectedBehavior, message)
}

func UnauthorizedUserError(message error) error {
	return createError(Unauthorized, authenicationFailed, message)
}

func UnauthorizedUser() error {
	return createErrorMsg(Unauthorized, authenicationFailed, defaultDetails)
}

func MissingAdminRights() error {
	return createErrorMsg(Forbidden, missingAdminRights, defaultDetails)
}

func IllegalArgument(message string) error {
	return createErrorMsg(BadData, illegalData, message)
}

func createError(code int, overall string, details error) error {
	return createErrorMsg(code, overall, details.Error())
}

func createErrorMsg(code int, overall string, details string) error {
	errorMsg := fmt.Sprintf(formatString, code, overall, details)
	return errors.New(errorMsg)
}

func RetrieveErrorCode(err error) int {
	_, code, e := splitMessageAndExtractCode(err)
	if e != nil {
		return Unexpected
	}
	return code
}

func RetrieveErrorMessage(err error) string {
	parts, _, e := splitMessageAndExtractCode(err)
	if e != nil {
		return err.Error()
	}
	return strings.TrimSpace(parts[1])
}

func splitMessageAndExtractCode(err error) ([]string, int, error) {
	parts := strings.Split(err.Error(), ":")
	if len(parts) < 3 {
		return parts, -1, nonFormatted
	}
	code, e := strconv.Atoi(parts[0])
	if e != nil {
		return parts, -1, nonFormatted
	}
	switch code {
	case BadData, Unexpected, Unauthorized, Forbidden:
		return parts, code, nil
	default:
		return parts, -1, nonFormatted
	}
}
