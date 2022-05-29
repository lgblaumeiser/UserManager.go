// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package util

import "testing"

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

	encoded := EncodeRoles(&roles)
	if encoded != roleString {
		t.Errorf("Encoding roles failed, expected %s, found %s", roleString, encoded)
	}

	if !TwoStringListsHaveSameContent(DecodeRoles(encoded), &roles) {
		t.Error("Roles do not match")
	}
}
