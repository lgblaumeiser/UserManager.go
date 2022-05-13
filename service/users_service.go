// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service

import (
	"errors"
	"strings"

	libs "github.com/lgblaumeiser/usermanager/functions"
)

const adminUser = "admin"
const adminPassword = "admin"
const adminRole = "user_admin"
const adminSuffix = "_admin"

var store UserStore

var AuthenticationFailed = errors.New("Authentication failed for user")
var IllegalArgument = errors.New("Given argument is not according to spec")
var UserNotFound = errors.New("The specified user has not been found in database")

func InitializeUserService(storeimpl UserStore) {
	store = storeimpl

	user := store.GetUser(adminUser)
	if user == nil {
		user = &User{adminUser, adminPassword, []string{adminRole}}
		store.StoreUser(user)
	}
}

func RegisterUserService(username string, password string, roles *[]string) (string, error) {
	if !libs.IsCleanAlphanumericString(username) {
		return "", libs.IllegalArgument("username")
	}
	if !libs.IsCleanString(password) {
		return "", libs.IllegalArgument("password")
	}
	if !areCleanRoles(roles) {
		return "", libs.IllegalArgument("roles")
	}
	if len(*roles) == 0 {
		return "", libs.IllegalArgument("at least one role")
	}

	roles, err := addAndRemoveRoles(&[]string{}, roles, &[]string{}, false)
	if err != nil {
		return "", err
	}
	var checkUser = store.GetUser(username)
	if checkUser != nil {
		return "", libs.IllegalArgument("user exists")
	}

	encryptedPW, err := libs.EncryptPassword(password)
	if err != nil {
		return "", err
	}

	newUser := User{username, encryptedPW, *roles}
	user, err := store.StoreUser(&newUser)
	if err != nil {
		return "", libs.UnexpectedBehaviorError(err)
	}
	return user, nil
}

func ChangePasswordService(username string, password string, requestor string) (string, error) {
	if !libs.IsCleanAlphanumericString(username) {
		return "", libs.IllegalArgument("username")
	}
	if !libs.IsCleanString(password) {
		return "", libs.IllegalArgument("password")
	}
	if !libs.IsCleanAlphanumericString(requestor) {
		return "", libs.IllegalArgument("requestor")
	}

	userObj := store.GetUser(username)
	if userObj == nil {
		return "", libs.IllegalArgument("unknown user")
	}

	_, err := properAdminAccess(userObj, requestor)
	if err != nil {
		return "", err
	}

	encryptedPW, err := libs.EncryptPassword(password)
	if err != nil {
		return "", err
	}

	changedUser := User{userObj.Username, encryptedPW, userObj.Roles}
	user, err := store.StoreUser(&changedUser)
	if err != nil {
		return "", libs.UnexpectedBehaviorError(err)
	}
	return user, nil
}

func ChangeRoles(username string, requestor string, newRoles *[]string, obsRoles *[]string) (string, error) {
	if !libs.IsCleanAlphanumericString(username) {
		return "", libs.IllegalArgument("username")
	}
	if !libs.IsCleanAlphanumericString(requestor) {
		return "", libs.IllegalArgument("requestor")
	}
	if !areCleanRoles(newRoles) {
		return "", libs.IllegalArgument("newRoles")
	}
	if !areCleanRoles(obsRoles) {
		return "", libs.IllegalArgument("obsRoles")
	}

	userObj := store.GetUser(username)
	if userObj == nil {
		return "", libs.IllegalArgument("unknown user")
	}

	admin, err := properAdminAccess(userObj, requestor)
	if err != nil {
		return "", err
	}

	changedRoles, err := addAndRemoveRoles(&userObj.Roles, newRoles, obsRoles, admin)
	if err != nil {
		return "", err
	}
	if len(*changedRoles) == 0 {
		return "", libs.IllegalArgument("no role left")
	}

	var changedUser = User{userObj.Username, userObj.Password, *changedRoles}
	user, err := store.StoreUser(&changedUser)
	if err != nil {
		return "", libs.UnexpectedBehaviorError(err)
	}
	return user, nil
}

func DeleteUser(username string, requestor string) error {
	if !libs.IsCleanAlphanumericString(username) {
		return libs.IllegalArgument("username")
	}
	if !libs.IsCleanAlphanumericString(requestor) {
		return libs.IllegalArgument("requestor")
	}

	if username == adminUser {
		return libs.IllegalArgument("Admin user cannot be deleted")
	}

	userObj := store.GetUser(username)
	if userObj == nil {
		return nil
	}

	admin, err := properAdminAccess(userObj, requestor)
	if err != nil {
		return err
	}
	if !admin {
		return libs.MissingAdminRights()
	}

	err = store.DeleteUser(userObj)
	if err != nil {
		return libs.UnexpectedBehaviorError(err)
	}
	return nil
}

func AuthenticateUser(username string, password string) (string, error) {
	if !libs.IsCleanAlphanumericString(username) {
		return "", libs.IllegalArgument("username")
	}
	if !libs.IsCleanString(password) {
		return "", libs.IllegalArgument("password")
	}

	userObj := store.GetUser(username)
	if userObj == nil {
		return "", libs.IllegalArgument("unknown user")
	}

	err := libs.CheckPassword(userObj.Password, password)
	if err != nil {
		return "", err
	}

	return libs.CreateToken(userObj.Username, &userObj.Roles)
}

func properAdminAccess(user *User, requestor string) (bool, error) {
	if user.Username != requestor {
		requestorObj := store.GetUser(requestor)
		if requestorObj == nil {
			return false, libs.IllegalArgument("unknown requestor")
		}
		if !isAdmin(requestorObj) {
			return false, libs.MissingAdminRights()
		}
		return true, nil
	}
	return isAdmin(user), nil
}

func isAdmin(user *User) bool {
	for _, role := range user.Roles {
		if role == adminRole {
			return true
		}
	}
	return false
}

func areCleanRoles(raw *[]string) bool {
	if raw == nil {
		return false
	}

	ok := true
	for _, rawRole := range *raw {
		ok = ok && libs.IsCleanAlphanumericString(rawRole)
	}
	return ok
}

func addAndRemoveRoles(roles *[]string, toAdd *[]string, toRemove *[]string, admin bool) (*[]string, error) {
	set := make(map[string]bool)
	for _, role := range *roles {
		set[role] = true
	}
	for _, role := range *toAdd {
		if !isAdminRole(role) || admin {
			set[role] = true
		} else {
			return nil, libs.MissingAdminRights()
		}
	}
	for _, role := range *toRemove {
		delete(set, role)
	}

	result := make([]string, 0)
	for key := range set {
		result = append(result, key)
	}
	return &result, nil
}

func isAdminRole(role string) bool {
	return strings.HasSuffix(role, adminSuffix)
}
