package functions

import (
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt"
	uuid "github.com/google/uuid"
)

const tokenDurationInHours = 18

var jwtKey []byte

func InitializeJwtService(key []byte) {
	jwtKey = key
}

func CreateToken(username string, roles string) (string, error) {
	if !IsCleanAlphanumericString(username) {
		return "", IllegalArgument("username must contain a trimmed string with content")
	}
	if !IsRoleString(roles) {
		return "", IllegalArgument("at least one roles must be defined")
	}

	expirationDate := time.Now().Add(tokenDurationInHours * time.Hour)
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return "", UnexpectedBehaviorError(err)
	}

	claims := jwt.MapClaims{
		"id":       tokenID,
		"username": username,
		"roles":    roles,
		"exp":      expirationDate.Unix(),
		"iat":      time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", UnexpectedBehaviorError(err)
	}

	return tokenString, nil
}

func ParseToken(tokenString string) (string, string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		return "", "", TokenValidationError(err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", TokenValidationError(err)
	}

	if !token.Valid {
		return "", "", TokenExpired()
	}

	username := claims["username"].(string)
	if len(strings.TrimSpace(username)) == 0 {
		return "", "", TokenValidation("Username not defined in token")
	}
	roles := claims["roles"].(string)
	return username, roles, nil
}
