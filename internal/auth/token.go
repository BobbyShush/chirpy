package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer: "chirpy",
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject: userID.String(),
	})
	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return tokenString, err
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if jwt.SigningMethodHS256.Alg() != token.Method.Alg() {
			return "", jwt.ErrSignatureInvalid
		}
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid or expired token. err: %w", err)
	}

	idString, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("couldn't find ID. err: %w", err)
	}

	id, err := uuid.Parse(idString)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("invalid ID. err: %w", err)
	}

	return id, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	bearerToken, exists := headers["Authorization"]
	if !exists {
		return "", errors.New("no authorization header found")
	}
	return strings.Split(bearerToken[0], " ")[1], nil
}

func MakeRefreshToken() (string, error) {
	randData := make([]byte, 32)
	_, err := rand.Read(randData)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(randData), nil
}