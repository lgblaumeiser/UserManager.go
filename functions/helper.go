package functions

import (
	"regexp"
	"strings"
)

func IsCleanString(raw string) bool {
	if len(raw) == 0 {
		return false
	}

	clean := strings.TrimSpace(raw)
	if len(clean) != len(raw) {
		return false
	}
	return true
}

var isAlphaNumeric = regexp.MustCompile(`^[A-Za-z0-9-_.]+$`).MatchString

func IsCleanAlphanumericString(raw string) bool {
	if !IsCleanString(raw) {
		return false
	}

	if !isAlphaNumeric(raw) {
		return false
	}

	return true
}
