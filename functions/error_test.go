package functions

import (
	"errors"
	"fmt"
	"testing"
)

const testOverall = "Test String"
const testDetails = "Test Details"

func TestErrorCreationMessage(t *testing.T) {
	err := createErrorMsg(BadData, testOverall, testDetails)
	checkError(t, err, BadData, testOverall, testDetails)
}

func TestErrorCreation(t *testing.T) {
	err := createError(Unauthorized, testOverall, errors.New(testDetails))
	checkError(t, err, Unauthorized, testOverall, testDetails)
}

func TestTokenValidationError(t *testing.T) {
	err := TokenValidationError(errors.New(testDetails))
	checkError(t, err, BadData, tokenValidationFailed, testDetails)
}

func TestTokenValidation(t *testing.T) {
	err := TokenValidation(testDetails)
	checkError(t, err, BadData, tokenValidationFailed, testDetails)
}

func TestUnexpectedBehaviorError(t *testing.T) {
	err := UnexpectedBehaviorError(errors.New(testDetails))
	checkError(t, err, Unexpected, unexpectedBehavior, testDetails)
}

func TestUnexpectedBehavior(t *testing.T) {
	err := UnexpectedBehavior(testDetails)
	checkError(t, err, Unexpected, unexpectedBehavior, testDetails)
}

func TestUnauthorizedUserError(t *testing.T) {
	err := UnauthorizedUserError(errors.New(testDetails))
	checkError(t, err, Unauthorized, authenicationFailed, testDetails)
}

func TestUnauthorizedUser(t *testing.T) {
	err := UnauthorizedUser()
	checkError(t, err, Unauthorized, authenicationFailed, defaultDetails)
}

func TestMissingAdminRights(t *testing.T) {
	err := MissingAdminRights()
	checkError(t, err, Forbidden, missingAdminRights, defaultDetails)
}

func TestIllegalArgument(t *testing.T) {
	err := IllegalArgument(testDetails)
	checkError(t, err, BadData, illegalData, testDetails)
}

func TestWithSimpleError(t *testing.T) {
	err := errors.New("Simple test string")
	checkNonFormatted(t, err, "Simple test string")
}

func TestWithNonFormattedErrorWithColon(t *testing.T) {
	err := errors.New("t: text: details")
	checkNonFormatted(t, err, "t: text: details")
}

func TestWithWrongCode(t *testing.T) {
	err := errors.New("-1: text: details")
	checkNonFormatted(t, err, "-1: text: details")
}

func checkNonFormatted(t *testing.T, err error, msg string) {
	code := RetrieveErrorCode(err)
	if code != Unexpected {
		t.Errorf("Wrong code for non-formatted error message")
	}
	emsg := RetrieveErrorMessage(err)
	if emsg != msg {
		t.Errorf("Wrong msg for non-formatted error message")
	}
}

func checkError(t *testing.T, err error, code int, overall string, details string) {
	foundCode := RetrieveErrorCode(err)
	if code != foundCode {
		t.Errorf("Wrong code: %d, should be %d", foundCode, code)
	}
	foundOverall := RetrieveErrorMessage(err)
	if overall != foundOverall {
		t.Errorf("Wrong overall message: '%s', should be '%s'", foundOverall, overall)
	}
	message := fmt.Sprintf(formatString, code, overall, details)
	if message != err.Error() {
		t.Errorf("Wrong error message: %s", err.Error())
	}

}
