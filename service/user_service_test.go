package service_test

import (
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
	initializeTesteeUserService(t)

	username, err := service.RegisterUserService(testUser, testPassword, &testRoles)
	if err != nil {
		t.Fatalf("Unexpected issue in register User: %s", err.Error())
	}
	if username != testUser {
		t.Fatalf("Username is not given properly, expected '%s', found '%s'", testUser, username)
	}

	token, err := service.AuthenticateUser(username, testPassword)
	if err != nil {
		t.Fatalf("Authenticate failed: %s", err.Error())
	}
	username, roles, err := libs.ParseToken(token)
	if err != nil {
		t.Fatalf("Token validation issue: %s", err.Error())
	}
	if username != testUser {
		t.Fatalf("Token username does not match, expected '%s', found '%s'", testUser, username)
	}
	if !compareRoles(&testRoles, roles) {
		t.Fatalf("Token roles do not match, expected '%s', found '%s'", strings.Join(testRoles, ";"), strings.Join(*roles, ";"))
	}

	_, err = service.AuthenticateUser(testUser, altPassword)
	if err == nil {
		t.Fatalf("Authentication with wrong password should fail")
	}
	if libs.RetrieveErrorCode(err) != libs.Unauthorized {
		t.Fatalf("Wrong error code, expected %d, found %d", libs.Unauthorized, libs.RetrieveErrorCode(err))
	}

	_, err = service.AuthenticateUser(altUser, testPassword)
	if err == nil {
		t.Fatalf("Authentication with unknown user should fail")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Fatalf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.AuthenticateUser("", testPassword)
	if err == nil {
		t.Fatalf("Authentication with empty user should fail")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Fatalf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.AuthenticateUser("$tr@ngr", testPassword)
	if err == nil {
		t.Fatalf("Authentication with non alphanumeric user should fail")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Fatalf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.AuthenticateUser(" strange", testPassword)
	if err == nil {
		t.Fatalf("Authentication with whitespaced user should fail")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Fatalf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.AuthenticateUser(testUser, "")
	if err == nil {
		t.Fatalf("Authentication with empty password should fail")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Fatalf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.AuthenticateUser(testUser, "\tsuper")
	if err == nil {
		t.Fatalf("Authentication with whitespaced password should fail")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Fatalf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}
}

func TestRegisterUserWrongData(t *testing.T) {
	initializeTesteeUserService(t)

	_, err := service.RegisterUserService("", testPassword, &testRoles)
	if err == nil {
		t.Errorf("Empty username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.RegisterUserService("str@ngeUser", testPassword, &testRoles)
	if err == nil {
		t.Errorf("Strange username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.RegisterUserService("\tsomething", testPassword, &testRoles)
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.RegisterUserService("some thing", testPassword, &testRoles)
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.RegisterUserService(testUser, "", &testRoles)
	if err == nil {
		t.Errorf("Empty password should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.RegisterUserService(testUser, "\tstrange", &testRoles)
	if err == nil {
		t.Errorf("Whitespaced password should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.RegisterUserService(testUser, testPassword, nil)
	if err == nil {
		t.Errorf("Roles nil should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.RegisterUserService(testUser, testPassword, &[]string{})
	if err == nil {
		t.Errorf("Empty roles should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.RegisterUserService(testUser, testPassword, &[]string{""})
	if err == nil {
		t.Errorf("Empty role should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.RegisterUserService(testUser, testPassword, &[]string{" somerole"})
	if err == nil {
		t.Errorf("Whitespaced role should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.RegisterUserService(testUser, testPassword, &[]string{"some role"})
	if err == nil {
		t.Errorf("Whitespaced role should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.RegisterUserService(testUser, testPassword, &[]string{"role_admin"})
	if err == nil {
		t.Errorf("Usage of admin role should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.Forbidden {
		t.Errorf("Wrong error code, expected %d, found %d", libs.Forbidden, libs.RetrieveErrorCode(err))
	}
}

func TestAuthenticationWrongDate(t *testing.T) {
	initializeTesteeUserService(t)

	_, err := service.AuthenticateUser("", testPassword)
	if err == nil {
		t.Errorf("Empty username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.AuthenticateUser("str@ngeUser", testPassword)
	if err == nil {
		t.Errorf("Strange username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.AuthenticateUser("\tsomething", testPassword)
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.AuthenticateUser("some thing", testPassword)
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.AuthenticateUser(testUser, "")
	if err == nil {
		t.Errorf("Empty password should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.AuthenticateUser(testUser, "\tstrange")
	if err == nil {
		t.Errorf("Whitespaced password should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}
}

func TestRegisterMultipleUsers(t *testing.T) {
	initializeTesteeUserService(t)

	username, err := service.RegisterUserService(testUser, testPassword, &testRoles)
	if err != nil {
		t.Fatalf("Unexpected issue in register User: %s", err.Error())
	}
	if username != testUser {
		t.Fatalf("Username is not given properly, expected '%s', found '%s'", testUser, username)
	}

	username2, err := service.RegisterUserService(altUser, altPassword, &altRoles)
	if err != nil {
		t.Fatalf("Unexpected issue in register User: %s", err.Error())
	}
	if username2 != altUser {
		t.Fatalf("Username is not given properly, expected '%s', found '%s'", altUser, username2)
	}

	_, err = service.RegisterUserService(testUser, altPassword, &altRoles)
	if err == nil {
		t.Fatalf("Register user a second time has to fail")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Fatalf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.AuthenticateUser(username, testPassword)
	if err != nil {
		t.Fatalf("Authenticate failed: %s", err.Error())
	}
}

func TestChangePassword(t *testing.T) {
	initializeTesteeUserService(t)

	_, err := service.RegisterUserService(testUser, testPassword, &testRoles)
	if err != nil {
		t.Fatalf("Error creating user: %s", err.Error())
	}

	_, err = service.RegisterUserService(altUser, altPassword, &altRoles)
	if err != nil {
		t.Fatalf("Error creating user: %s", err.Error())
	}

	username, err := service.ChangePasswordService(testUser, "ChangedPW", testUser)
	if err != nil {
		t.Fatalf("Unexpected error changing password: %s", err.Error())
	}
	if username != testUser {
		t.Fatalf("Unexpected username returned, expected %s, found %s", testUser, username)
	}
	_, err = service.AuthenticateUser(testUser, "ChangedPW")
	if err != nil {
		t.Fatalf("Authentication failed with new password: %s", err.Error())
	}

	username, err = service.ChangePasswordService(testUser, "AnotherChanged", adminUser)
	if err != nil {
		t.Fatalf("Unexpected error changing password: %s", err.Error())
	}
	if username != testUser {
		t.Fatalf("Unexpected username returned, expected %s, found %s", testUser, username)
	}
	_, err = service.AuthenticateUser(testUser, "AnotherChanged")
	if err != nil {
		t.Fatalf("Authentication failed with new password: %s", err.Error())
	}

	_, err = service.ChangePasswordService(testUser, "Yacp", altUser)
	if err == nil {
		t.Fatalf("Error expected for change password with different but non-admin requestor")
	}
	if libs.RetrieveErrorCode(err) != libs.Forbidden {
		t.Fatalf("Wrong error received, expected %d, received %d", libs.Forbidden, libs.RetrieveErrorCode(err))
	}
	_, err = service.AuthenticateUser(testUser, "AnotherChanged")
	if err != nil {
		t.Fatalf("Authentication failed with new password: %s", err.Error())
	}

	_, err = service.ChangePasswordService(testUser, "yacp", "unknown")
	if err == nil {
		t.Fatalf("Error expected for change password with unknown requestor")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Fatalf("Wrong error received, expected %d, received %d", libs.BadData, libs.RetrieveErrorCode(err))
	}
	_, err = service.AuthenticateUser(testUser, "AnotherChanged")
	if err != nil {
		t.Fatalf("Authentication failed with new password: %s", err.Error())
	}

	_, err = service.ChangePasswordService("unknown", "yacp", adminUser)
	if err == nil {
		t.Fatalf("Error expected for change password with unknown user")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Fatalf("Wrong error received, expected %d, received %d", libs.BadData, libs.RetrieveErrorCode(err))
	}
}

func TestChangePasswordWrongData(t *testing.T) {
	initializeTesteeUserService(t)

	_, err := service.ChangePasswordService("", testPassword, adminUser)
	if err == nil {
		t.Errorf("Empty username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangePasswordService("str@ngeUser", testPassword, adminUser)
	if err == nil {
		t.Errorf("Strange username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangePasswordService("\tsomething", testPassword, adminUser)
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangePasswordService("some thing", testPassword, adminUser)
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangePasswordService(testUser, "", adminUser)
	if err == nil {
		t.Errorf("Empty password should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangePasswordService(testUser, "\tstrange", adminUser)
	if err == nil {
		t.Errorf("Whitespaced password should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangePasswordService(testUser, testPassword, "")
	if err == nil {
		t.Errorf("Empty requestor should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangePasswordService(testUser, testPassword, "str@ngeUser")
	if err == nil {
		t.Errorf("Strange username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangePasswordService(testUser, testPassword, "\tsomething")
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangePasswordService(testUser, testPassword, "some thing")
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}
}

func TestChangeRoles(t *testing.T) {
	initializeTesteeUserService(t)

	_, err := service.RegisterUserService(testUser, testPassword, &testRoles)
	if err != nil {
		t.Fatalf("Error creating user: %s", err.Error())
	}

	_, err = service.RegisterUserService(altUser, altPassword, &altRoles)
	if err != nil {
		t.Fatalf("Error creating user: %s", err.Error())
	}

	username, err := service.ChangeRoles(testUser, testUser, &altRoles, &[]string{testRoles[1], testRoles[2]})
	if err != nil {
		t.Fatalf("Unexpected error changing roles: %s", err.Error())
	}
	if username != testUser {
		t.Fatalf("Unexpected username returned, expected %s, found %s", testUser, username)
	}
	expectedRoles := []string{testRoles[0], altRoles[0], altRoles[1]}
	foundRoles := extractRolesForUserPW(testUser, testPassword, t)
	if !compareRoles(&expectedRoles, foundRoles) {
		t.Fatalf("Token roles do not match, expected '%s', found '%s'", strings.Join(expectedRoles, ";"), strings.Join(*foundRoles, ";"))
	}

	username, err = service.ChangeRoles(testUser, adminUser, &[]string{testRoles[1], testRoles[2]}, &altRoles)
	if err != nil {
		t.Fatalf("Unexpected error changing roles: %s", err.Error())
	}
	if username != testUser {
		t.Fatalf("Unexpected username returned, expected %s, found %s", testUser, username)
	}
	foundRoles = extractRolesForUserPW(testUser, testPassword, t)
	if !compareRoles(&testRoles, foundRoles) {
		t.Fatalf("Token roles do not match, expected '%s', found '%s'", strings.Join(testRoles, ";"), strings.Join(*foundRoles, ";"))
	}

	username, err = service.ChangeRoles(testUser, adminUser, &[]string{}, &[]string{testRoles[0], testRoles[1], testRoles[2]})
	if err == nil {
		t.Fatalf("Error expected changing roles with no roles left")
	}
	foundRoles = extractRolesForUserPW(testUser, testPassword, t)
	if !compareRoles(&testRoles, foundRoles) {
		t.Fatalf("Token roles do not match, expected '%s', found '%s'", strings.Join(testRoles, ";"), strings.Join(*foundRoles, ";"))
	}

	_, err = service.ChangeRoles(testUser, altUser, &altRoles, &[]string{testRoles[1], testRoles[2]})
	if err == nil {
		t.Fatalf("Error expected for change roles with different but non-admin requestor")
	}
	if libs.RetrieveErrorCode(err) != libs.Forbidden {
		t.Fatalf("Wrong error received, expected %d, received %d", libs.Forbidden, libs.RetrieveErrorCode(err))
	}
	foundRoles = extractRolesForUserPW(testUser, testPassword, t)
	if !compareRoles(&testRoles, foundRoles) {
		t.Fatalf("Token roles do not match, expected '%s', found '%s'", strings.Join(testRoles, ";"), strings.Join(*foundRoles, ";"))
	}

	_, err = service.ChangeRoles(testUser, "unknown", &altRoles, &[]string{testRoles[1], testRoles[2]})
	if err == nil {
		t.Fatalf("Error expected for change roles with unknown requestor")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Fatalf("Wrong error received, expected %d, received %d", libs.BadData, libs.RetrieveErrorCode(err))
	}
	foundRoles = extractRolesForUserPW(testUser, testPassword, t)
	if !compareRoles(&testRoles, foundRoles) {
		t.Fatalf("Token roles do not match, expected '%s', found '%s'", strings.Join(testRoles, ";"), strings.Join(*foundRoles, ";"))
	}

	_, err = service.ChangeRoles("unknown", adminUser, &altRoles, &[]string{testRoles[1], testRoles[2]})
	if err == nil {
		t.Fatalf("Error expected for change roles with unknown requestor")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Fatalf("Wrong error received, expected %d, received %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	username, err = service.ChangeRoles(testUser, testUser, &adminRoles, &[]string{})
	if err == nil {
		t.Fatalf("Adding admin roles should only be possible by admin user")
	}
	if libs.RetrieveErrorCode(err) != libs.Forbidden {
		t.Fatalf("Wrong error received, expected %d, received %d", libs.Forbidden, libs.RetrieveErrorCode(err))
	}

	username, err = service.ChangeRoles(testUser, adminUser, &adminRoles, &[]string{})
	if err != nil {
		t.Fatalf("Unexpected error changing roles: %s", err.Error())
	}
	if username != testUser {
		t.Fatalf("Unexpected username returned, expected %s, found %s", testUser, username)
	}
	expectedRoles = []string{testRoles[0], testRoles[1], testRoles[2], adminRoles[0]}
	foundRoles = extractRolesForUserPW(testUser, testPassword, t)
	if !compareRoles(&expectedRoles, foundRoles) {
		t.Fatalf("Token roles do not match, expected '%s', found '%s'", strings.Join(expectedRoles, ";"), strings.Join(*foundRoles, ";"))
	}
}

func TestChangeRolesWrongData(t *testing.T) {
	initializeTesteeUserService(t)

	_, err := service.ChangeRoles("", adminUser, &testRoles, &altRoles)
	if err == nil {
		t.Errorf("Empty username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles("str@ngeUser", adminUser, &testRoles, &altRoles)
	if err == nil {
		t.Errorf("Strange username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles("\tsomething", adminUser, &testRoles, &altRoles)
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles("some thing", adminUser, &testRoles, &altRoles)
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles(testUser, "", &testRoles, &altRoles)
	if err == nil {
		t.Errorf("Empty requestor should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles(testUser, "str@ngeUser", &testRoles, &altRoles)
	if err == nil {
		t.Errorf("Strange username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles(testUser, "\tsomething", &testRoles, &altRoles)
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles(testUser, "some thing", &testRoles, &altRoles)
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles(testUser, testPassword, nil, &[]string{})
	if err == nil {
		t.Errorf("Roles nil should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles(testUser, testPassword, &[]string{""}, &[]string{})
	if err == nil {
		t.Errorf("Empty role should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles(testUser, testPassword, &[]string{" somerole"}, &[]string{})
	if err == nil {
		t.Errorf("Whitespaced role should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles(testUser, testPassword, &[]string{"some role"}, &[]string{})
	if err == nil {
		t.Errorf("Whitespaced role should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles(testUser, testPassword, &[]string{}, nil)
	if err == nil {
		t.Errorf("Roles nil should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles(testUser, testPassword, &[]string{}, &[]string{""})
	if err == nil {
		t.Errorf("Empty role should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles(testUser, testPassword, &[]string{}, &[]string{" somerole"})
	if err == nil {
		t.Errorf("Whitespaced role should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	_, err = service.ChangeRoles(testUser, testPassword, &[]string{}, &[]string{"some role"})
	if err == nil {
		t.Errorf("Whitespaced role should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}
}

func TestDeleteUser(t *testing.T) {
	initializeTesteeUserService(t)

	_, err := service.RegisterUserService(testUser, testPassword, &testRoles)
	if err != nil {
		t.Fatalf("Error creating user: %s", err.Error())
	}

	_, err = service.RegisterUserService(altUser, altPassword, &altRoles)
	if err != nil {
		t.Fatalf("Error creating user: %s", err.Error())
	}

	err = service.DeleteUser(testUser, testUser)
	if err == nil {
		t.Fatalf("Delete user not allowed for user itself, admin required")
	}
	if libs.RetrieveErrorCode(err) != libs.Forbidden {
		t.Fatalf("Wrong error code, expected %d, found %d", libs.Forbidden, libs.RetrieveErrorCode(err))
	}

	err = service.DeleteUser(testUser, altUser)
	if err == nil {
		t.Fatalf("Delete user not allowed for non-admin user, admin required")
	}
	if libs.RetrieveErrorCode(err) != libs.Forbidden {
		t.Fatalf("Wrong error code, expected %d, found %d", libs.Forbidden, libs.RetrieveErrorCode(err))
	}

	err = service.DeleteUser(testUser, "unknown")
	if err == nil {
		t.Fatalf("Delete user not possible if requestor is unknown")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Fatalf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	err = service.DeleteUser("unknown", adminUser)
	if err != nil {
		t.Fatalf("Unexpected Error: %s", err.Error())
	}

	_, err = service.ChangeRoles(altUser, adminUser, &[]string{"user_admin"}, &[]string{})
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}

	err = service.DeleteUser(testUser, adminUser)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}

	err = service.DeleteUser(altUser, adminUser)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}

	err = service.DeleteUser(adminUser, adminUser)
	if err == nil {
		t.Fatalf("Expected error, because 'admin' user is not allowed to be removed")
	}
}

func TestDeleteUserWrongData(t *testing.T) {
	initializeTesteeUserService(t)

	err := service.DeleteUser("", adminUser)
	if err == nil {
		t.Errorf("Empty username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	err = service.DeleteUser("str@ngeUser", adminUser)
	if err == nil {
		t.Errorf("Strange username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	err = service.DeleteUser("\tsomething", adminUser)
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	err = service.DeleteUser("some thing", adminUser)
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	err = service.DeleteUser(testUser, "")
	if err == nil {
		t.Errorf("Empty requestor should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	err = service.DeleteUser(testUser, "str@ngeUser")
	if err == nil {
		t.Errorf("Strange username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	err = service.DeleteUser(testUser, "\tsomething")
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}

	err = service.DeleteUser(testUser, "some thing")
	if err == nil {
		t.Errorf("Whitespaced username should result in error")
	}
	if libs.RetrieveErrorCode(err) != libs.BadData {
		t.Errorf("Wrong error code, expected %d, found %d", libs.BadData, libs.RetrieveErrorCode(err))
	}
}

func extractRolesForUserPW(username string, password string, t *testing.T) *[]string {
	token, err := service.AuthenticateUser(username, password)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}

	_, roles, err := libs.ParseToken(token)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err.Error())
	}

	return roles
}

func compareRoles(testRoles *[]string, roles *[]string) bool {
	if len(*testRoles) != len(*roles) {
		return false
	}
	for _, outer := range *testRoles {
		ok := false
		for _, inner := range *roles {
			if inner == outer {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func initializeTesteeUserService(t *testing.T) {
	key, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("Cannot create key: %s", err.Error())
	}
	libs.InitializeJwtService([]byte(key.String()))

	store := store.CreateMemoryStore()
	service.InitializeUserService(store)
}
