// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service

import (
	"strings"

	"github.com/google/uuid"
	"github.com/lgblaumeiser/usermanager/util"
)

const AdminRole = "usermanager_admin"
const UserRole = "usermanager_user"

const adminUser = "admin"
const adminPassword = "admin"
const adminSuffix = "_admin"

type UserService struct {
	store UserStore
}

func NewUserService(storeimpl UserStore) (UserService, *util.RestError) {
	usrv := UserService{storeimpl}

	user := usrv.store.GetUser(adminUser)
	if user == nil {
		encryptedPW, err := util.EncryptPassword(adminPassword)
		if err != nil {
			return usrv, err
		}

		user = &User{adminUser, encryptedPW, &[]string{AdminRole}, ""}
		usrv.store.AddUser(user)
	}

	return usrv, nil
}

func (us *UserService) RegisterUser(username string, password string, roles *[]string) (string, *util.RestError) {
	if !util.IsCleanAlphanumericString(username) {
		return "", util.IllegalArgument("username")
	}
	if !util.IsCleanString(password) {
		return "", util.IllegalArgument("password")
	}
	if !us.areCleanRoles(roles) {
		return "", util.IllegalArgument("roles")
	}
	newRoles, err := us.addAndRemoveRoles(&[]string{}, roles, &[]string{}, false)
	if err != nil {
		return "", err
	}

	encryptedPW, err := util.EncryptPassword(password)
	if err != nil {
		return "", err
	}

	newUser := User{username, encryptedPW, newRoles, ""}
	user, ok, gerr := us.store.AddUser(&newUser)
	if gerr != nil {
		return "", util.UnexpectedBehavior(&gerr)
	}
	if !ok {
		return "", util.IllegalArgument("user exists")
	}
	return user, nil
}

func (us *UserService) ChangePassword(username string, password string, requestor string) (string, *util.RestError) {
	if username == "" {
		username = requestor
	}
	if !util.IsCleanAlphanumericString(username) {
		return "", util.IllegalArgument("username")
	}
	if !util.IsCleanString(password) {
		return "", util.IllegalArgument("password")
	}
	if !util.IsCleanAlphanumericString(requestor) {
		return "", util.UnauthorizedUser()
	}

	userObj := us.store.GetUser(username)
	if userObj == nil {
		return "", util.IllegalArgument("unknown user")
	}

	_, err := us.properAdminAccess(userObj, requestor)
	if err != nil {
		return "", err
	}

	encryptedPW, err := util.EncryptPassword(password)
	if err != nil {
		return "", err
	}

	changedUser := User{userObj.Username, encryptedPW, userObj.Roles, userObj.RefreshToken}
	user, gerr := us.store.StoreUser(&changedUser)
	if gerr != nil {
		return "", util.UnexpectedBehavior(&gerr)
	}
	return user, nil
}

func (us *UserService) ChangeRoles(username string, requestor string, newRoles *[]string, obsRoles *[]string) (string, *util.RestError) {
	if username == "" {
		username = requestor
	}
	if !util.IsCleanAlphanumericString(username) {
		return "", util.IllegalArgument("username")
	}
	if !util.IsCleanAlphanumericString(requestor) {
		return "", util.UnauthorizedUser()
	}
	if !us.areCleanRoles(newRoles) {
		return "", util.IllegalArgument("newRoles")
	}
	if !us.areCleanRoles(obsRoles) {
		return "", util.IllegalArgument("obsRoles")
	}

	userObj := us.store.GetUser(username)
	if userObj == nil {
		return "", util.IllegalArgument("unknown user")
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
		return "", util.IllegalArgument("no role left")
	}

	var changedUser = User{userObj.Username, userObj.Password, changedRoles, userObj.RefreshToken}
	user, gerr := us.store.StoreUser(&changedUser)
	if gerr != nil {
		return "", util.UnexpectedBehavior(&gerr)
	}
	return user, nil
}

func (us *UserService) DeleteUser(username string, requestor string) *util.RestError {
	if !util.IsCleanAlphanumericString(username) {
		return util.IllegalArgument("username")
	}
	if !util.IsCleanAlphanumericString(requestor) {
		return util.UnauthorizedUser()
	}

	if username == adminUser {
		return util.IllegalArgument("admin user cannot be deleted")
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
		return util.MissingAdminRights()
	}

	gerr := us.store.DeleteUser(userObj)
	if err != nil {
		return util.UnexpectedBehavior(&gerr)
	}
	return nil
}

func (us *UserService) AuthenticateUser(username string, password string) (string, string, *util.RestError) {
	if !util.IsCleanAlphanumericString(username) {
		return "", "", util.IllegalArgument("username")
	}
	if !util.IsCleanString(password) {
		return "", "", util.IllegalArgument("password")
	}

	userObj := us.store.GetUser(username)
	if userObj == nil {
		return "", "", util.UnauthorizedUser()
	}

	err := util.CheckPassword(userObj.Password, password)
	if err != nil {
		return "", "", err
	}

	accessToken, refreshToken, refreshId, err := util.CreateToken(userObj.Username, userObj.Roles)
	userObj.RefreshToken = refreshId
	_, ioerr := us.store.StoreUser(userObj)
	if ioerr != nil {
		return "", "", util.UnexpectedBehavior(&ioerr)
	}
	return accessToken, refreshToken, err
}

func (us *UserService) RefreshToken(username string, tokenId string) (string, string, *util.RestError) {
	if !util.IsCleanAlphanumericString(username) {
		return "", "", util.IllegalArgument("username")
	}

	if _, err := uuid.Parse(tokenId); err != nil {
		return "", "", util.IllegalArgument("tokenId")
	}

	userObj := us.store.GetUser(username)
	if userObj == nil {
		return "", "", util.UnauthorizedUser()
	}

	if tokenId != userObj.RefreshToken {
		return "", "", util.UnauthorizedUser()
	}

	accessToken, refreshToken, refreshId, err := util.CreateToken(userObj.Username, userObj.Roles)
	userObj.RefreshToken = refreshId
	_, ioerr := us.store.StoreUser(userObj)
	if ioerr != nil {
		return "", "", util.UnexpectedBehavior(&ioerr)
	}
	return accessToken, refreshToken, err
}

func (us *UserService) InvalidateToken(username string) *util.RestError {
	if !util.IsCleanAlphanumericString(username) {
		return util.IllegalArgument("username")
	}

	userObj := us.store.GetUser(username)
	if userObj == nil {
		return nil
	}

	userObj.RefreshToken = ""

	_, err := us.store.StoreUser(userObj)
	if err != nil {
		return util.UnexpectedBehavior(&err)
	}

	return nil
}

func (us *UserService) Backup(requestor string) (*[]byte, *util.RestError) {
	if !util.IsCleanAlphanumericString(requestor) {
		return nil, util.UnauthorizedUser()
	}

	requestorObj := us.store.GetUser(requestor)
	if !us.isAdmin(requestorObj) {
		return nil, util.MissingAdminRights()
	}

	userList := us.store.GetUsers()
	byteMap := map[string][]byte{}
	for _, user := range *userList {
		encodedUser, err := EncodeUser(&user)
		if err != nil {
			return nil, util.UnexpectedBehavior(&err)
		}
		byteMap[user.Username] = encodedUser
	}

	zippedData, err := util.ZipContent(&byteMap)
	if err != nil {
		return nil, util.UnexpectedBehavior(&err)
	}
	return &zippedData, nil
}

func (us *UserService) Restore(requestor string, userData *[]byte) *util.RestError {
	if !util.IsCleanAlphanumericString(requestor) {
		return util.UnauthorizedUser()
	}

	requestorObj := us.store.GetUser(requestor)
	if !us.isAdmin(requestorObj) {
		return util.MissingAdminRights()
	}

	restoreData := []User{}
	userMap, err := util.UnzipContent(*userData)
	if err != nil {
		return util.UnexpectedBehavior(&err)
	}
	for _, data := range userMap {
		user, err := DecodeUser(data)
		if err != nil {
			return util.UnexpectedBehavior(&err)
		}
		restoreData = append(restoreData, *user)
	}

	err = us.store.RestoreUsers(&restoreData)
	if err != nil {
		return util.UnexpectedBehavior(&err)
	}

	return nil
}

func (us *UserService) properAdminAccess(user *User, requestor string) (bool, *util.RestError) {
	if user.Username != requestor {
		requestorObj := us.store.GetUser(requestor)
		if requestorObj == nil {
			return false, util.IllegalArgument("unknown requestor")
		}
		if !us.isAdmin(requestorObj) {
			return false, util.MissingAdminRights()
		}
		return true, nil
	} else {
		return us.isAdmin(user), nil
	}
}

func (us *UserService) isAdmin(user *User) bool {
	if user != nil {
		for _, role := range *user.Roles {
			if role == AdminRole {
				return true
			}
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
		ok = ok && util.IsCleanAlphanumericString(rawRole)
	}
	return ok
}

func (us *UserService) addAndRemoveRoles(roles *[]string, toAdd *[]string, toRemove *[]string, admin bool) (*[]string, *util.RestError) {
	set := make(map[string]struct{})
	for _, role := range *roles {
		set[role] = struct{}{}
	}
	for _, role := range *toAdd {
		if !us.isAdminRole(role) || admin {
			set[role] = struct{}{}
		} else {
			return nil, util.MissingAdminRights()
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
