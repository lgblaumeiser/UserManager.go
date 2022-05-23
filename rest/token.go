// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package rest

import (
	"net/http"
	"strings"

	"github.com/lgblaumeiser/usermanager/util"
)

const UsernameHeader = "username"
const TokenIdHeader = "tokenid"

func TokenReader(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if len(token) > 0 {
			token = strings.Replace(token, "Bearer ", "", 1)
			user, _, id, err := util.ParseToken(token)
			if err == nil {
				r.Header.Set(UsernameHeader, user)
				r.Header.Set(TokenIdHeader, id)
			}
		}
		inner.ServeHTTP(w, r)
	})
}
