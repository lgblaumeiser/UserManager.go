// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package service_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/lgblaumeiser/usermanager/service"
)

const username = "TestUser"
const password = "SomeHashedPassword"

var roles = []string{"TestRole"}

func TestJsonEncoding(t *testing.T) {
	testData := service.User{username, password, &roles}

	encoded, err := service.EncodeUser(&testData)
	if err != nil {
		t.Fatalf("Error occured: %s", err.Error())
	}

	retrieved, err := service.DecodeUser(encoded)
	if err != nil {
		t.Fatalf("Error occured: %s", err.Error())
	}

	if !cmp.Equal(testData, *retrieved) {
		t.Fatalf("Not Equal, expected: {%s, %s, %s}, retrieved: {%s, %s, %s}",
			testData.Username, testData.Password, (*testData.Roles)[0], retrieved.Username, retrieved.Password, (*retrieved.Roles)[0])
	}
}
