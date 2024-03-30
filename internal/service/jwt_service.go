package service

import (
	"auth/internal/entities"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt"
)

type jwtService struct {
	secretKey string
}

func NewJWTService() *jwtService {
	return &jwtService{secretKey: os.Getenv("AUTH_SERVER_SECRET_KEY")}
}

func (s jwtService) Generate(ttl int64) (string, error) {
	return entities.NewAccessTokenPayload(ttl).Token().SignedString([]byte(s.secretKey))
}

func (s jwtService) Validate(tokenValidating string) (bool, error) {
	token, err := entities.JWTParse(tokenValidating, s.secretKey)
	if err != nil {
		return false, err
	}

	if !token.Valid {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				return false, fmt.Errorf("token expired")
			}
		}
	}

	return true, nil
}
