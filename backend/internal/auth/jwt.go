package auth

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var defaultSecret = []byte(getEnv("JWT_SECRET_KEY", "your-super-secret-key-change-this-in-production-12345"))

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	DeviceID string `json:"device_id,omitempty"`
	Sub      string `json:"sub,omitempty"`
	jwt.RegisteredClaims
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func VerifyPassword(password, hash string) bool {
	return CheckPassword(password, hash)
}

func GenerateToken(username, role, deviceID string, duration time.Duration) (string, error) {
	now := time.Now().UTC()
	sub := username
	if deviceID != "" {
		sub = deviceID
	}

	claims := Claims{
		Username: username,
		Role:     role,
		DeviceID: deviceID,
		Sub:      sub,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(defaultSecret)
}

func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return defaultSecret, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		if claims.Username == "" && claims.Subject != "" {
			claims.Username = claims.Subject
		}
		return claims, nil
	}

	return nil, errors.New("invalid token claims")
}

func CreateAccessToken(username, role, secret string, duration time.Duration) (string, error) {
	sec := defaultSecret
	if secret != "" {
		sec = []byte(secret)
	}
	claims := Claims{
		Username: username,
		Role:     role,
		Sub:      username,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(sec)
}

func DecodeAccessToken(tokenString, secret string) (string, string, error) {
	sec := defaultSecret
	if secret != "" {
		sec = []byte(secret)
	}
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return sec, nil
	})
	if err != nil {
		return "", "", err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		sub := claims.Subject
		if sub == "" {
			sub = claims.Username
		}
		return sub, claims.Role, nil
	}
	return "", "", errors.New("invalid token claims")
}
