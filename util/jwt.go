// SPDX-FileCopyrightText: 2022 Lars Geyer-Blaumeiser <lars@lgblaumeiser.de>
// SPDX-License-Identifier: MIT
package util

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

var emptyList = []string{}

const accessTokenDurationInMinutes = 30
const refreshTokenDurationInDays = 14

var jwtKey []byte

func InitializeJwtService(key []byte) {
	jwtKey = key
}

func ParseToken(tokenString string) (string, *[]string, *RestError) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return "", &emptyList, UnexpectedBehavior(&err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", &emptyList, UnexpectedBehavior(&err)
	}

	if !token.Valid {
		return "", &emptyList, TokenExpired()
	}

	username := claims["username"].(string)
	if len(strings.TrimSpace(username)) == 0 {
		wrapped := errors.New("Username not defined in token")
		return "", &emptyList, UnexpectedBehavior(&wrapped)
	}
	roles := ""
	rawRoles := claims["roles"]
	if rawRoles != nil {
		roles = rawRoles.(string)
		if !isRoleString(roles) {
			wrapped := errors.New("Roles not defined in token")
			return "", &emptyList, UnexpectedBehavior(&wrapped)
		}
	}
	return username, decodeRoles(roles), nil
}

// Returns accessToken, refreshToken, refreshTokenId, potential error
func CreateToken(username string, roles *[]string) (string, string, string, *RestError) {
	if !IsCleanAlphanumericString(username) {
		return "", "", "", IllegalArgument("username")
	}
	roleString := encodeRoles(roles)
	if !isRoleString(roleString) {
		return "", "", "", IllegalArgument("roles")
	}

	accessToken, _, err := createTokenWithClaims(accessTokenDurationInMinutes, jwt.MapClaims{
		"username": username,
		"roles":    roleString,
	})
	if err != nil {
		return "", "", "", err
	}

	refreshToken, refreshId, err := createTokenWithClaims(refreshTokenDurationInDays*24*60, jwt.MapClaims{"username": username})
	if err != nil {
		return "", "", "", err
	}

	return accessToken, refreshToken, refreshId, nil
}

func createTokenWithClaims(duration time.Duration, claims jwt.MapClaims) (string, string, *RestError) {
	expirationDate := time.Now().Add(duration * time.Minute)
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return "", "", UnexpectedBehavior(&err)
	}

	claims["id"] = tokenID
	claims["exp"] = expirationDate.Unix()
	claims["iat"] = time.Now().Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", "", UnexpectedBehavior(&err)
	}

	return tokenString, tokenID.String(), nil
}

var isRoleList = regexp.MustCompile(`^[A-Za-z0-9-_.;]+$`).MatchString

func isRoleString(raw string) bool {
	return len(raw) > 0 && isRoleList(raw)
}

func encodeRoles(roles *[]string) string {
	if roles == nil || len(*roles) == 0 {
		return ""
	}
	return strings.Join(*roles, RoleSeparator)
}

func decodeRoles(roles string) *[]string {
	if roles == "" {
		return nil
	}
	rolelist := strings.Split(roles, RoleSeparator)
	return &rolelist
}
