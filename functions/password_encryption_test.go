package functions

import "testing"

const testPassword = "My c00l Te$tpassword"

func TestCleanPasswordEncryption(t *testing.T) {
	encryptedPassword, err := EncryptPassword(testPassword)
	if err != nil {
		t.Errorf("Error while encrypting password: %s", err.Error())
	}

	err = CheckPassword(encryptedPassword, testPassword)
	if err != nil {
		t.Errorf("Check of password failed: %s", err.Error())
	}
}

func TestPasswordCheckShouldFailForWrongPassword(t *testing.T) {
	encryptedPassword, err := EncryptPassword(testPassword)
	if err != nil {
		t.Errorf("Error while encrypting password: %s", err.Error())
	}

	err = CheckPassword(encryptedPassword, "Some other stuff")
	if err == nil {
		t.Errorf("The check of a password that does not match the encrypted must fail")
	}
	if RetrieveErrorCode(err) != Unauthorized {
		t.Errorf("Wrong error code, should be %d, is %d", Unauthorized, RetrieveErrorCode(err))
	}
}

func TestEmptyPasswordShouldFail(t *testing.T) {
	_, err := EncryptPassword("")
	if err == nil {
		t.Errorf("Empty password should fail")
	}
	if RetrieveErrorCode(err) != BadData {
		t.Errorf("Wrong error code, should be %d, is %d", BadData, RetrieveErrorCode(err))
	}
}
