package entities

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

type TokenType string

const (
	Access TokenType = "ACCESS_TOKEN_TYPE"
)

type TokenPayload struct {
	Authorized bool      `json:"authorized"`
	Exp        int64     `json:"exp"`
	Type       TokenType `json:"type"`
}

func NewAccessTokenPayload(ttl int64) TokenPayload {
	return TokenPayload{
		Authorized: true,
		Exp:        time.Now().Add(time.Hour * time.Duration(ttl)).Unix(),
		Type:       Access,
	}
}

func (payload TokenPayload) Valid() error {
	if !payload.Authorized {
		return fmt.Errorf("Unauthorized")
	}

	if time.Now().After(time.Unix(payload.Exp, 0)) {
		return fmt.Errorf("Unauthorized")
	}
	return nil
}

func (payload TokenPayload) Token() *jwt.Token {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = payload.Authorized
	claims["exp"] = payload.Exp
	claims["type"] = payload.Type
	return token
}

func JWTParse(tokenValidating, secretKey string) (*jwt.Token, error) {
	var tokenClaims TokenPayload
	token, err := jwt.ParseWithClaims(tokenValidating, &tokenClaims, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("there was an error in parsing")
		} else if method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("there was an error in parsing")
		}
		return []byte(secretKey), nil
	})

	return token, err
}
