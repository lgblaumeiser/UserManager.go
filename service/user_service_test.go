// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/lgblaumeiser/usermanager/service"
	"github.com/lgblaumeiser/usermanager/store"
	"github.com/lgblaumeiser/usermanager/util"
)

func TestUserAuthentificationService(t *testing.T) {
	us := initializeTesteeUserService(t)

	result, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	access, refresh, err := us.AuthenticateUser(result, testPassword)
	if ok, message := checkAuthenticationResult(testUser, &testRoles, access, refresh, err); !ok {
		t.Fatal(message)
	}

	access, refresh, err = us.AuthenticateUser(adminUser, adminPassword)
	if ok, message := checkAuthenticationResult(adminUser, &[]string{service.AdminRole}, access, refresh, err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser(testUser, altPassword)
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser(altUser, testPassword)
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
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
	if ok, message := checkError(err, http.StatusForbidden); !ok {
		t.Fatal(message)
	}
}

func TestAuthenticationWrongDate(t *testing.T) {
	us := initializeTesteeUserService(t)

	_, _, err := us.AuthenticateUser("", testPassword)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser("str@ngeUser", testPassword)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser("\tsomething", testPassword)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser("some thing", testPassword)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser(testUser, "")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser(testUser, "\tstrange")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}
}

func TestRegisterMultipleUsers(t *testing.T) {
	us := initializeTesteeUserService(t)

	result, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}
	username := result

	result, err = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, result, err); !ok {
		t.Fatal(message)
	}

	_, err = us.RegisterUser(testUser, altPassword, &altRoles)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser(username, testPassword)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}
}

func TestChangePassword(t *testing.T) {
	us := initializeTesteeUserService(t)

	result, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	result, err = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, result, err); !ok {
		t.Fatal(message)
	}

	result, err = us.ChangePassword(testUser, "ChangedPW", testUser)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser(testUser, "ChangedPW")
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}

	result, err = us.ChangePassword("", "ChangedPWAgain", testUser)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	result, err = us.ChangePassword(testUser, "AnotherChanged", adminUser)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser(testUser, "AnotherChanged")
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword(testUser, "Yacp", altUser)
	if ok, message := checkError(err, http.StatusForbidden); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser(testUser, "AnotherChanged")
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword(testUser, "yacp", "unknown")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.AuthenticateUser(testUser, "AnotherChanged")
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

	_, err := us.ChangePassword("str@ngeUser", testPassword, adminUser)
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
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword(testUser, testPassword, "str@ngeUser")
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword(testUser, testPassword, "\tsomething")
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangePassword(testUser, testPassword, "some thing")
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}
}

func TestChangeRoles(t *testing.T) {
	us := initializeTesteeUserService(t)

	result, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	result, err = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, result, err); !ok {
		t.Fatal(message)
	}

	result, err = us.ChangeRoles(testUser, testUser, &altRoles, &[]string{testRoles[1], testRoles[2]})
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &[]string{testRoles[0], altRoles[0], altRoles[1]}, &us); !ok {
		t.Fatal(message)
	}

	result, err = us.ChangeRoles("", testUser, &[]string{testRoles[2]}, &[]string{testRoles[0]})
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &[]string{testRoles[2], altRoles[0], altRoles[1]}, &us); !ok {
		t.Fatal(message)
	}

	result, err = us.ChangeRoles(testUser, adminUser, &[]string{testRoles[0], testRoles[1]}, &altRoles)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &testRoles, &us); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, altUser, &altRoles, &[]string{})
	if ok, message := checkError(err, http.StatusForbidden); !ok {
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

	result, err = us.ChangeRoles(testUser, adminUser, &[]string{}, &[]string{testRoles[0], testRoles[1], testRoles[2]})
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &[]string{}, &us); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, testUser, &adminRoles, &[]string{})
	if ok, message := checkError(err, http.StatusForbidden); !ok {
		t.Fatal(message)
	}

	result, err = us.ChangeRoles(testUser, adminUser, &adminRoles, &[]string{})
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &[]string{adminRoles[0]}, &us); !ok {
		t.Fatal(message)
	}

	result, err = us.ChangeRoles(testUser, adminUser, &[]string{service.AdminRole}, &[]string{})
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}
	if ok, message := checkRolesForUserPW(testUser, testPassword, &[]string{service.AdminRole, adminRoles[0]}, &us); !ok {
		t.Fatal(message)
	}
}

func TestChangeRolesWrongData(t *testing.T) {
	us := initializeTesteeUserService(t)

	_, err := us.ChangeRoles("str@ngeUser", adminUser, &testRoles, &altRoles)
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
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, "str@ngeUser", &testRoles, &altRoles)
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, "\tsomething", &testRoles, &altRoles)
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, "some thing", &testRoles, &altRoles)
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, adminUser, nil, &[]string{})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, adminUser, &[]string{""}, &[]string{})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, adminUser, &[]string{" somerole"}, &[]string{})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, adminUser, &[]string{"some role"}, &[]string{})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, adminUser, &[]string{}, nil)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, adminUser, &[]string{}, &[]string{""})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, adminUser, &[]string{}, &[]string{" somerole"})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, err = us.ChangeRoles(testUser, adminUser, &[]string{}, &[]string{"some role"})
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}
}

func TestDeleteUser(t *testing.T) {
	us := initializeTesteeUserService(t)

	result, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	result, err = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, result, err); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(testUser, testUser)
	if ok, message := checkError(err, http.StatusForbidden); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(testUser, altUser)
	if ok, message := checkError(err, http.StatusForbidden); !ok {
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

	result, err = us.ChangeRoles(altUser, adminUser, &[]string{"user_admin"}, &[]string{})
	if ok, message := checkUsernameResult(altUser, result, err); !ok {
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
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(testUser, "str@ngeUser")
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(testUser, "\tsomething")
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}

	err = us.DeleteUser(testUser, "some thing")
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}
}

func TestRefreshToken(t *testing.T) {
	us := initializeTesteeUserService(t)

	result, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	access, refresh, err := us.AuthenticateUser(testUser, testPassword)
	if ok, message := checkAuthenticationResult(testUser, &testRoles, access, refresh, err); !ok {
		t.Fatal(message)
	}

	userObj := userStore.GetUser(testUser)
	id, uerr := uuid.Parse(userObj.RefreshToken)
	if uerr != nil {
		t.Fatal("Refresh token id not ok")
	}

	access, refresh, err = us.RefreshToken(testUser, id.String())
	if ok, message := checkAuthenticationResult(testUser, &testRoles, access, refresh, err); !ok {
		t.Fatal(message)
	}

	userObj = userStore.GetUser(testUser)
	id2, uerr := uuid.Parse(userObj.RefreshToken)
	if err != nil {
		t.Fatal("Refresh token id not ok")
	}
	if id == id2 {
		t.Fatal("Stored token id unchanged after refresh")
	}

	access, refresh, err = us.RefreshToken(testUser, id2.String())
	if ok, message := checkAuthenticationResult(testUser, &testRoles, access, refresh, err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.RefreshToken(testUser, id2.String())
	if ok, message := checkError(err, http.StatusUnauthorized); !ok {
		t.Fatal(message)
	}
}

func TestRefreshWrongData(t *testing.T) {
	us := initializeTesteeUserService(t)

	testUuid, uerr := uuid.NewRandom()
	if uerr != nil {
		t.Fatal("UUid generation failed")
	}
	uuidString := testUuid.String()

	_, _, err := us.RefreshToken("", uuidString)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.RefreshToken("str@ngeUser", uuidString)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.RefreshToken("\tsomething", uuidString)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.RefreshToken("some thing", uuidString)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	_, _, err = us.RefreshToken(testUser, uninteresting)
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}
}

func TestInvalidate(t *testing.T) {
	us := initializeTesteeUserService(t)

	result, err := us.RegisterUser(testUser, testPassword, &testRoles)
	if ok, message := checkUsernameResult(testUser, result, err); !ok {
		t.Fatal(message)
	}

	result, err = us.RegisterUser(altUser, altPassword, &altRoles)
	if ok, message := checkUsernameResult(altUser, result, err); !ok {
		t.Fatal(message)
	}

	access, refresh, err := us.AuthenticateUser(testUser, testPassword)
	if ok, message := checkAuthenticationResult(testUser, &testRoles, access, refresh, err); !ok {
		t.Fatal(message)
	}

	userObj := userStore.GetUser(testUser)
	if _, err := uuid.Parse(userObj.RefreshToken); err != nil {
		t.Fatal("Refresh token id not ok")
	}

	err = us.InvalidateToken(testUser)
	if ok, message := checkUnexpectedError(err); !ok {
		t.Fatal(message)
	}

	userObj = userStore.GetUser(testUser)
	if userObj.RefreshToken != "" {
		t.Fatal("Refresh token id exists after invalidation")
	}
}

func TestInvalidateWrongData(t *testing.T) {
	us := initializeTesteeUserService(t)

	err := us.InvalidateToken("")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	err = us.InvalidateToken("str@ngeUser")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	err = us.InvalidateToken("\tsomething")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}

	err = us.InvalidateToken("some thing")
	if ok, message := checkWrongData(err); !ok {
		t.Fatal(message)
	}
}

var userStore service.UserStore

func initializeTesteeUserService(t *testing.T) service.UserService {
	key, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("Cannot create key: %s", err.Error())
	}
	util.InitializeJwtService([]byte(key.String()))

	userStore = store.CreateMemoryStore()
	usrv, serr := service.NewUserService(userStore)
	if ok, message := checkUnexpectedError(serr); !ok {
		t.Fatal(message)
	}

	return usrv
}
