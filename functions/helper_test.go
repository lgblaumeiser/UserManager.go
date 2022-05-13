// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package functions

import "testing"

func TestIsCleanString(t *testing.T) {
	if !IsCleanString("&fsdlj2/tf") {
		t.Errorf("string check failed")
	}

	if IsCleanString("") {
		t.Errorf("string check failed")
	}

	if IsCleanString("\t") {
		t.Errorf("string check failed")
	}

	if IsCleanString("\n") {
		t.Errorf("string check failed")
	}

	if IsCleanString("\t   ksdjf9") {
		t.Errorf("string check failed")
	}

	if IsCleanString("jkasdhf8&837\n") {
		t.Errorf("string check failed")
	}
}

func TestIsAlphanumericString(t *testing.T) {
	if !IsCleanAlphanumericString("aBZ7_.78-gT") {
		t.Errorf("string check failed")
	}

	if !IsCleanAlphanumericString("_aBZ7gT") {
		t.Errorf("string check failed")
	}

	if IsCleanAlphanumericString("a$6783") {
		t.Errorf("string check failed")
	}

	if IsCleanAlphanumericString("  6dfahkj") {
		t.Errorf("string check failed")
	}
}

func TestIsRoleString(t *testing.T) {
	if !IsRoleString("aBZ7_.78-gT;fjksdafh") {
		t.Errorf("string check failed")
	}

	if !IsRoleString("_aBZ7gT") {
		t.Errorf("string check failed")
	}

	if IsRoleString("a$6783;hgz") {
		t.Errorf("string check failed")
	}

	if IsRoleString("  6dfahkj;\t65dfhj") {
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

	for _, outer := range *DecodeRoles(encoded) {
		found := false
		for _, inner := range roles {
			if outer == inner {
				found = true
			}
		}
		if !found {
			t.Errorf("Role not found %s", outer)
		}
	}

}
