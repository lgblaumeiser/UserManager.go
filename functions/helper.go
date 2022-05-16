// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package functions

import (
	"regexp"
	"strings"
)

const RoleSeparator = ";"

func IsCleanString(raw string) bool {
	return len(raw) > 0 && len(raw) == len(strings.TrimSpace(raw))
}

var isAlphaNumeric = regexp.MustCompile(`^[A-Za-z0-9-_.]+$`).MatchString

func IsCleanAlphanumericString(raw string) bool {
	return len(raw) > 0 && isAlphaNumeric(raw)
}

func TwoStringListsHaveSameContent(left *[]string, right *[]string) bool {
	if len(*left) != len(*right) {
		return false
	}

	for _, item := range *left {
		if !Contains(right, item) {
			return false
		}
	}

	return true
}

func Contains(list *[]string, content string) bool {
	for _, item := range *list {
		if item == content {
			return true
		}
	}
	return false
}
