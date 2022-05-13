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
