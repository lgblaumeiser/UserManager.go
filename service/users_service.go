// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service

import (
	"strings"

	libs "github.com/lgblaumeiser/usermanager/functions"
)

const AdminRole = "usermanager_admin"
const UserRole = "usermanager_user"

const adminUser = "admin"
const adminPassword = "admin"
const adminSuffix = "_admin"

type UserService struct {
	store UserStore
}

type User struct {
	Username string

	Password string

	Roles *[]string
}

func NewUserService(storeimpl UserStore) UserService {
	usrv := UserService{storeimpl}

	user := usrv.store.GetUser(adminUser)
	if user == nil {
		user = &User{adminUser, adminPassword, &[]string{AdminRole}}
		usrv.store.StoreUser(user)
	}

	return usrv
}

func (us *UserService) RegisterUser(username string, password string, roles *[]string) (string, *libs.RestError) {
	if !libs.IsCleanAlphanumericString(username) {
		return "", libs.IllegalArgument("username")
	}
	if !libs.IsCleanString(password) {
		return "", libs.IllegalArgument("password")
	}
	if !us.areCleanRoles(roles) {
		return "", libs.IllegalArgument("roles")
	}
	newRoles, err := us.addAndRemoveRoles(&[]string{}, roles, &[]string{}, false)
	if err != nil {
		return "", err
	}

	encryptedPW, err := libs.EncryptPassword(password)
	if err != nil {
		return "", err
	}

	newUser := User{username, encryptedPW, newRoles}
	user, ok, gerr := us.store.AddUser(&newUser)
	if gerr != nil {
		return "", libs.UnexpectedBehavior(&gerr)
	}
	if !ok {
		return "", libs.IllegalArgument("user exists")
	}
	return user, nil
}

func (us *UserService) ChangePassword(username string, password string, requestor string) (string, *libs.RestError) {
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
	user, gerr := us.store.StoreUser(&changedUser)
	if gerr != nil {
		return "", libs.UnexpectedBehavior(&gerr)
	}
	return user, nil
}

func (us *UserService) ChangeRoles(username string, requestor string, newRoles *[]string, obsRoles *[]string) (string, *libs.RestError) {
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

	changedRoles, err := us.addAndRemoveRoles(userObj.Roles, newRoles, obsRoles, admin)
	if err != nil {
		return "", err
	}
	if len(*changedRoles) == 0 {
		return "", libs.IllegalArgument("no role left")
	}

	var changedUser = User{userObj.Username, userObj.Password, changedRoles}
	user, gerr := us.store.StoreUser(&changedUser)
	if gerr != nil {
		return "", libs.UnexpectedBehavior(&gerr)
	}
	return user, nil
}

func (us *UserService) DeleteUser(username string, requestor string) *libs.RestError {
	if !libs.IsCleanAlphanumericString(username) {
		return libs.IllegalArgument("username")
	}
	if !libs.IsCleanAlphanumericString(requestor) {
		return libs.IllegalArgument("requestor")
	}

	if username == adminUser {
		return libs.IllegalArgument("admin user cannot be deleted")
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

	gerr := us.store.DeleteUser(userObj)
	if err != nil {
		return libs.UnexpectedBehavior(&gerr)
	}
	return nil
}

func (us *UserService) AuthenticateUser(username string, password string) (string, *libs.RestError) {
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

	user, err := libs.CreateToken(userObj.Username, userObj.Roles)
	return user, err
}

func (us *UserService) Backup(requestor string) (*[]User, *libs.RestError) {
	if !libs.IsCleanAlphanumericString(requestor) {
		return nil, libs.IllegalArgument("requestor")
	}

	requestorObj := us.store.GetUser(requestor)
	if !us.isAdmin(requestorObj) {
		return nil, libs.MissingAdminRights()
	}
	return us.store.GetUsers(), nil
}

func (us *UserService) Restore(requestor string, users *[]User) *libs.RestError {
	if !libs.IsCleanAlphanumericString(requestor) {
		return libs.IllegalArgument("requestor")
	}

	requestorObj := us.store.GetUser(requestor)
	if !us.isAdmin(requestorObj) {
		return libs.MissingAdminRights()
	}

	for _, user := range *users {
		existing := us.store.GetUser(user.Username)
		if existing == nil {
			_, _, err := us.store.AddUser(&user)
			if err != nil {
				return libs.UnexpectedBehavior(&err)
			}
		} else {
			adaptedRoles, rerr := us.addAndRemoveRoles(user.Roles, existing.Roles, &[]string{}, true)
			if rerr != nil {
				return rerr
			}
			adaptedUser := User{user.Username, existing.Password, adaptedRoles}
			_, err := us.store.StoreUser(&adaptedUser)
			if err != nil {
				return libs.UnexpectedBehavior(&err)
			}
		}
	}

	return nil
}

func (us *UserService) properAdminAccess(user *User, requestor string) (bool, *libs.RestError) {
	if user.Username != requestor {
		requestorObj := us.store.GetUser(requestor)
		if requestorObj == nil {
			return false, libs.IllegalArgument("unknown requestor")
		}
		if !us.isAdmin(requestorObj) {
			return false, libs.MissingAdminRights()
		}
		return true, nil
	} else {
		return us.isAdmin(user), nil
	}
}

func (us *UserService) isAdmin(user *User) bool {
	for _, role := range *user.Roles {
		if role == AdminRole {
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

func (us *UserService) addAndRemoveRoles(roles *[]string, toAdd *[]string, toRemove *[]string, admin bool) (*[]string, *libs.RestError) {
	set := make(map[string]struct{})
	for _, role := range *roles {
		set[role] = struct{}{}
	}
	for _, role := range *toAdd {
		if !us.isAdminRole(role) || admin {
			set[role] = struct{}{}
		} else {
			return nil, libs.MissingAdminRights()
		}
	}
	for _, role := range *toRemove {
		delete(set, role)
	}

	_, uok := set[UserRole]
	_, aok := set[AdminRole]
	if !uok && !aok {
		set[UserRole] = struct{}{}
	}
	if uok && aok {
		delete(set, UserRole)
	}

	result := []string{}
	for key := range set {
		result = append(result, key)
	}
	return &result, nil
}

func (us *UserService) isAdminRole(role string) bool {
	return strings.HasSuffix(role, adminSuffix)
}
