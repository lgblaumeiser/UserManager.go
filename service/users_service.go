// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service

import (
	"strings"

	libs "github.com/lgblaumeiser/usermanager/functions"
)

const adminUser = "admin"
const adminPassword = "admin"
const adminRole = "user_admin"
const adminSuffix = "_admin"

type UserService struct {
	store UserStore
}

func NewUserService(storeimpl UserStore) UserService {
	usrv := UserService{storeimpl}

	user := usrv.store.GetUser(adminUser)
	if user == nil {
		user = &User{adminUser, adminPassword, adminRole}
		usrv.store.StoreUser(user)
	}

	return usrv
}

func (us *UserService) RegisterUser(username string, password string, roles *[]string) (string, error) {
	if !libs.IsCleanAlphanumericString(username) {
		return "", libs.IllegalArgument("username")
	}
	if !libs.IsCleanString(password) {
		return "", libs.IllegalArgument("password")
	}
	if !us.areCleanRoles(roles) {
		return "", libs.IllegalArgument("roles")
	}
	if len(*roles) == 0 {
		return "", libs.IllegalArgument("at least one role")
	}

	roleString, err := us.addAndRemoveRoles(&[]string{}, roles, &[]string{}, false)
	if err != nil {
		return "", err
	}
	var checkUser = us.store.GetUser(username)
	if checkUser != nil {
		return "", libs.IllegalArgument("user exists")
	}

	encryptedPW, err := libs.EncryptPassword(password)
	if err != nil {
		return "", err
	}

	newUser := User{username, encryptedPW, roleString}
	user, err := us.store.StoreUser(&newUser)
	if err != nil {
		return "", libs.UnexpectedBehaviorError(err)
	}
	return user, nil
}

func (us *UserService) ChangePassword(username string, password string, requestor string) (string, error) {
	if !libs.IsCleanAlphanumericString(username) {
		return "", libs.IllegalArgument("username")
	}
	if !libs.IsCleanString(password) {
		return "", libs.IllegalArgument("password")
	}
	if !libs.IsCleanAlphanumericString(requestor) {
		return "", libs.IllegalArgument("requestor")
	}

	userObj := us.store.GetUser(username)
	if userObj == nil {
		return "", libs.IllegalArgument("unknown user")
	}

	_, err := us.properAdminAccess(userObj, requestor)
	if err != nil {
		return "", err
	}

	encryptedPW, err := libs.EncryptPassword(password)
	if err != nil {
		return "", err
	}

	changedUser := User{userObj.Username, encryptedPW, userObj.Roles}
	user, err := us.store.StoreUser(&changedUser)
	if err != nil {
		return "", libs.UnexpectedBehaviorError(err)
	}
	return user, nil
}

func (us *UserService) ChangeRoles(username string, requestor string, newRoles *[]string, obsRoles *[]string) (string, error) {
	if !libs.IsCleanAlphanumericString(username) {
		return "", libs.IllegalArgument("username")
	}
	if !libs.IsCleanAlphanumericString(requestor) {
		return "", libs.IllegalArgument("requestor")
	}
	if !us.areCleanRoles(newRoles) {
		return "", libs.IllegalArgument("newRoles")
	}
	if !us.areCleanRoles(obsRoles) {
		return "", libs.IllegalArgument("obsRoles")
	}

	userObj := us.store.GetUser(username)
	if userObj == nil {
		return "", libs.IllegalArgument("unknown user")
	}

	admin, err := us.properAdminAccess(userObj, requestor)
	if err != nil {
		return "", err
	}

	changedRoles, err := us.addAndRemoveRoles(libs.DecodeRoles(userObj.Roles), newRoles, obsRoles, admin)
	if err != nil {
		return "", err
	}
	if len(changedRoles) == 0 {
		return "", libs.IllegalArgument("no role left")
	}

	var changedUser = User{userObj.Username, userObj.Password, changedRoles}
	user, err := us.store.StoreUser(&changedUser)
	if err != nil {
		return "", libs.UnexpectedBehaviorError(err)
	}
	return user, nil
}

func (us *UserService) DeleteUser(username string, requestor string) error {
	if !libs.IsCleanAlphanumericString(username) {
		return libs.IllegalArgument("username")
	}
	if !libs.IsCleanAlphanumericString(requestor) {
		return libs.IllegalArgument("requestor")
	}

	if username == adminUser {
		return libs.IllegalArgument("Admin user cannot be deleted")
	}

	userObj := us.store.GetUser(username)
	if userObj == nil {
		return nil
	}

	admin, err := us.properAdminAccess(userObj, requestor)
	if err != nil {
		return err
	}
	if !admin {
		return libs.MissingAdminRights()
	}

	err = us.store.DeleteUser(userObj)
	if err != nil {
		return libs.UnexpectedBehaviorError(err)
	}
	return nil
}

func (us *UserService) AuthenticateUser(username string, password string) (string, error) {
	if !libs.IsCleanAlphanumericString(username) {
		return "", libs.IllegalArgument("username")
	}
	if !libs.IsCleanString(password) {
		return "", libs.IllegalArgument("password")
	}

	userObj := us.store.GetUser(username)
	if userObj == nil {
		return "", libs.IllegalArgument("unknown user")
	}

	err := libs.CheckPassword(userObj.Password, password)
	if err != nil {
		return "", err
	}

	return libs.CreateToken(userObj.Username, userObj.Roles)
}

func (us *UserService) properAdminAccess(user *User, requestor string) (bool, error) {
	if user.Username != requestor {
		requestorObj := us.store.GetUser(requestor)
		if requestorObj == nil {
			return false, libs.IllegalArgument("unknown requestor")
		}
		if !us.isAdmin(requestorObj) {
			return false, libs.MissingAdminRights()
		}
		return true, nil
	}
	return us.isAdmin(user), nil
}

func (us *UserService) isAdmin(user *User) bool {
	roles := libs.DecodeRoles(user.Roles)
	for _, role := range *roles {
		if role == adminRole {
			return true
		}
	}
	return false
}

func (us *UserService) areCleanRoles(raw *[]string) bool {
	if raw == nil {
		return false
	}

	ok := true
	for _, rawRole := range *raw {
		ok = ok && libs.IsCleanAlphanumericString(rawRole)
	}
	return ok
}

func (us *UserService) addAndRemoveRoles(roles *[]string, toAdd *[]string, toRemove *[]string, admin bool) (string, error) {
	set := map[string]bool{}
	for _, role := range *roles {
		set[role] = true
	}
	for _, role := range *toAdd {
		if !us.isAdminRole(role) || admin {
			set[role] = true
		} else {
			return "", libs.MissingAdminRights()
		}
	}
	for _, role := range *toRemove {
		delete(set, role)
	}

	result := make([]string, 0)
	for key := range set {
		result = append(result, key)
	}
	return libs.EncodeRoles(&result), nil
}

func (us *UserService) isAdminRole(role string) bool {
	return strings.HasSuffix(role, adminSuffix)
}
