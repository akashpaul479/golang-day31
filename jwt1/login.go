package jwt1

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var SecretKey = []byte("My_Secret_Key")

func GenerateJwt(UserID int, email string) (string, error) {
	Claims := jwt.MapClaims{
		"user_id": UserID,
		"email":   email,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims)
	return token.SignedString(SecretKey)
}
