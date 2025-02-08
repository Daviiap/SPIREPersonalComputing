package utils

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserInfo struct {
	Name         string
	Email        string
	Organization string
}

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func GenerateToken(userInfo UserInfo) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name":         userInfo.Name,
		"email":        userInfo.Email,
		"organization": userInfo.Organization,
		"exp":          time.Now().Add(24 * time.Hour).Unix(),
	})

	return token.SignedString(jwtSecret)
}

func ValidateToken(tokenString string) (*UserInfo, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userInfo := &UserInfo{
			Name:         claims["name"].(string),
			Email:        claims["email"].(string),
			Organization: claims["organization"].(string),
		}
		return userInfo, nil
	}

	return nil, fmt.Errorf("invalid token")
}
