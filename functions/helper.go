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

var isRoleList = regexp.MustCompile(`^[A-Za-z0-9-_.;]+$`).MatchString

func IsRoleString(raw string) bool {
	return len(raw) > 0 && isRoleList(raw)
}

func EncodeRoles(roles *[]string) string {
	return strings.Join(*roles, RoleSeparator)
}

func DecodeRoles(roles string) *[]string {
	rolelist := strings.Split(roles, RoleSeparator)
	return &rolelist
}
