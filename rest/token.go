// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package rest

import (
	"net/http"
	"strings"

	libs "github.com/lgblaumeiser/usermanager/functions"
	"github.com/lgblaumeiser/usermanager/service"
)

const UsernameHeader = "username"
const RoleHeader = "roles"

func TokenReader(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if len(token) > 0 {
			token = strings.Replace(token, "Bearer ", "", 1)
			user, roles, err := libs.ParseToken(token)
			if err == nil {
				r.Header.Set(UsernameHeader, user)
				r.Header.Set(RoleHeader, extractRole(roles))
			}
		}
		inner.ServeHTTP(w, r)
	})
}

func extractRole(roles *[]string) string {
	currentRelevant := ""
	for _, role := range *roles {
		currentRelevant = getMoreImportantRole(role, currentRelevant)
	}
	return currentRelevant
}

func getMoreImportantRole(toCheck string, currentHigh string) string {
	if toCheck == service.AdminRole || currentHigh == service.AdminRole {
		return service.AdminRole
	} else if toCheck == service.UserRole || currentHigh == service.UserRole {
		return service.UserRole
	} else {
		return ""
	}
}
