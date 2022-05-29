// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package util

import (
	"regexp"
	"strings"
)

var isRoleList = regexp.MustCompile(`^[A-Za-z0-9-_.;]+$`).MatchString

func isRoleString(raw string) bool {
	return len(raw) > 0 && isRoleList(raw)
}

func EncodeRoles(roles *[]string) string {
	if roles == nil || len(*roles) == 0 {
		return ""
	}
	return strings.Join(*roles, RoleSeparator)
}

func DecodeRoles(roles string) *[]string {
	if roles == "" {
		return nil
	}
	rolelist := strings.Split(roles, RoleSeparator)
	return &rolelist
}
