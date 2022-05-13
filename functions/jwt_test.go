package functions

import (
	"testing"

	uuid "github.com/google/uuid"
)

var testUsername = "happyuser"
var testRoles = []string{"some_admin", "some_role", "another_role"}

func TestTokenCleanPath(t *testing.T) {
	initializeTesteeJwt(t)

	token, err := CreateToken(testUsername, &testRoles)
	if err != nil {
		t.Errorf("Create Token failed: %s", err.Error())
	}

	puser, proles, err := ParseToken(token)
	if err != nil {
		t.Errorf("Parse Token failed: %s", err.Error())
	}
	if puser != testUsername {
		t.Errorf("Expexted username: %s ; found username: %s", testUsername, puser)
	}
	if len(testRoles) != len(*proles) {
		t.Errorf("Role size mismatch, expected %d, found %d", len(testRoles), len(*proles))
	}
	for _, role := range *proles {
		found := false
		for _, inner := range testRoles {
			if role == inner {
				found = true
			}
		}
		if !found {
			t.Errorf("Role not found %s", role)
		}
	}
}

func TestWithEmptyUsername(t *testing.T) {
	initializeTesteeJwt(t)

	_, err := CreateToken("", &testRoles)
	if err == nil {
		t.Errorf("Create Token should have failed")
	}
}

func TestWithWhitespaceUsername(t *testing.T) {
	initializeTesteeJwt(t)

	_, err := CreateToken("  \t", &testRoles)
	if err == nil {
		t.Errorf("Create Token should have failed")
	}
}

func TestWithNilRoles(t *testing.T) {
	initializeTesteeJwt(t)

	_, err := CreateToken(testUsername, nil)
	if err == nil {
		t.Errorf("Create Token should have failed")
	}
}

func TestWithEmptyRoles(t *testing.T) {
	initializeTesteeJwt(t)

	emptyList := make([]string, 1)
	_, err := CreateToken(testUsername, &emptyList)
	if err == nil {
		t.Errorf("Create Token should have failed")
	}
}

func TestWithWrongKey(t *testing.T) {
	initializeTesteeJwt(t)

	token, err := CreateToken(testUsername, &testRoles)
	if err != nil {
		t.Errorf("Token creation failed: %s", err.Error())
	}

	InitializeJwtService([]byte("Another Key"))
	_, _, err = ParseToken(token)
	if err == nil {
		t.Errorf("Token validation should have failed")
	}
}

func initializeTesteeJwt(t *testing.T) {
	key, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("Cannot create key: %s", err.Error())
	}
	InitializeJwtService([]byte(key.String()))
}
