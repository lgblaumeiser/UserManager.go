// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package util

import (
	"testing"

	"github.com/google/uuid"
)

var testUsername = "happyuser"
var testRoles = []string{"some_admin", "some_role", "another_role"}

func TestTokenCleanPath(t *testing.T) {
	initializeTesteeJwt(t)

	accessToken, refreshToken, refreshId, err := CreateToken(testUsername, &testRoles)
	if err != nil {
		t.Errorf("Create Token failed: %s", err.Error())
	}

	puser, proles, _, err := ParseToken(accessToken)
	if err != nil {
		t.Errorf("Parse access token failed: %s", err.Error())
	}
	if puser != testUsername {
		t.Errorf("Expexted username: %s ; found username: %s", testUsername, puser)
	}
	if !TwoStringListsHaveSameContent(&testRoles, proles) {
		t.Errorf("Role size mismatch, expected %s, found %s", encodeRoles(&testRoles), encodeRoles(proles))
	}

	puser, proles, tokenId, err := ParseToken(refreshToken)
	if err != nil {
		t.Errorf("Parse refresh token failed: %s", err.Error())
	}
	if puser != testUsername {
		t.Errorf("Expexted username: %s ; found username: %s", testUsername, puser)
	}
	if proles != nil {
		t.Error("Expected roles to be empty for refresh token")
	}
	if refreshId != tokenId {
		t.Errorf("Token Id mismatch: expected: %s, found: %s", refreshId, tokenId)
	}
}

func TestWithWrongData(t *testing.T) {
	initializeTesteeJwt(t)

	_, _, _, err := CreateToken("", &testRoles)
	if err == nil {
		t.Errorf("Create Token should have failed")
	}
	initializeTesteeJwt(t)

	_, _, _, err = CreateToken("  \t", &testRoles)
	if err == nil {
		t.Errorf("Create Token should have failed")
	}
	initializeTesteeJwt(t)

	_, _, _, err = CreateToken(testUsername, nil)
	if err == nil {
		t.Errorf("Create Token should have failed")
	}

	_, _, _, err = CreateToken(testUsername, &emptyList)
	if err == nil {
		t.Errorf("Create Token should have failed")
	}
}

func TestWithWrongKey(t *testing.T) {
	initializeTesteeJwt(t)

	token, _, _, err := CreateToken(testUsername, &testRoles)
	if err != nil {
		t.Errorf("Token creation failed: %s", err.Error())
	}

	InitializeJwtService([]byte("Another Key"))
	_, _, _, err = ParseToken(token)
	if err == nil {
		t.Errorf("Token validation should have failed")
	}
}

func TestIsRoleString(t *testing.T) {
	if !isRoleString("aBZ7_.78-gT;fjksdafh") {
		t.Errorf("string check failed")
	}

	if !isRoleString("_aBZ7gT") {
		t.Errorf("string check failed")
	}

	if isRoleString("a$6783;hgz") {
		t.Errorf("string check failed")
	}

	if isRoleString("  6dfahkj;\t65dfhj") {
		t.Errorf("string check failed")
	}
}

func TestRoleListEncoding(t *testing.T) {
	roles := []string{"role_1", "role_2", "role_3"}
	roleString := "role_1;role_2;role_3"

	encoded := encodeRoles(&roles)
	if encoded != roleString {
		t.Errorf("Encoding roles failed, expected %s, found %s", roleString, encoded)
	}

	if !TwoStringListsHaveSameContent(decodeRoles(encoded), &roles) {
		t.Error("Roles do not match")
	}
}

func initializeTesteeJwt(t *testing.T) {
	key, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("Cannot create key: %s", err.Error())
	}
	InitializeJwtService([]byte(key.String()))
}
