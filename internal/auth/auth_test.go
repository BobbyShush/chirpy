package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword_Regular(t *testing.T) {
	password := "12345"
	hashedPw, err := HashPassword(password)
	if err != nil || hashedPw == "" {
		t.Errorf(`Failed hash. Returned string = %s. Err: %v`, hashedPw, err)
	}
}

func TestHashPassword_TooLong(t *testing.T) {
	// Test 2 - Too long
	password := "123456789012345678901234567890123456789012345678901234567890123456789012334567890"
	hashedPw, err := HashPassword(password)
	if err == nil {
		t.Errorf(`Failed hash. Returned string = %s. Err: %v`, hashedPw, err)
	}
}

func TestHashPassword_Empty(t *testing.T) {
	password := ""
	hashedPw, err := HashPassword(password)
	if err != nil || hashedPw == "" {
		t.Errorf(`Failed hash. Returned string = %s. Err: %v`, hashedPw, err)
	}
}

func TestCheckPasswordHash_Correct(t *testing.T) {
	password := "12345"
	hashedPw, err := HashPassword(password)
	if err != nil || hashedPw == "" {
		t.Errorf(`Failed hash. Returned string = %s. Err: %v`, hashedPw, err)
	} 
	err = CheckPasswordHash(hashedPw, password)
	if err != nil {
		t.Errorf(`Password check failed. Err: %v`, err)
	}
}

func TestCheckPasswordHash_Incorrect(t *testing.T) {
	password := "12345"
	hashedPw, err := HashPassword(password)
	if err != nil || hashedPw == "" {
		t.Errorf(`Failed hash. Returned string = %s. Err: %v`, hashedPw, err)
	} 
	err = CheckPasswordHash(hashedPw, "54321")
	if err == nil {
		t.Errorf(`Password check failed. Err: %v`, err)
	}
}

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "12345"
	expiresIn := 2 * time.Second
	tokenString, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil || tokenString == "" {
		t.Errorf("Couldn't create token. Err: %v", err)
	}
}

func TestValidateJWT_Regular(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "12345"
	expiresIn := 2 * time.Second
	tokenString, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil || tokenString == "" {
		t.Errorf("Couldn't create token. Err: %v", err)
	}

	validatedId, err := ValidateJWT(tokenString, tokenSecret)
	if err != nil || validatedId != userID {
		t.Errorf("Validation failed. %v != %v. Err: %v", userID, validatedId, err)
	}
}

func TestValidateJWT_Expired(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "12345"
	expiresIn := 1 * time.Nanosecond
	tokenString, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil || tokenString == "" {
		t.Errorf("Couldn't create token. Err: %v", err)
	}

	time.Sleep(2 * time.Nanosecond)

	_, err = ValidateJWT(tokenString, tokenSecret)
	if err == nil {
		t.Errorf("Validation failed. Token should be expired")
	}
}

func TestValidateJWT_Wrong(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "12345"
	expiresIn := 2 * time.Second
	tokenString, err := MakeJWT(userID, tokenSecret, expiresIn)
	if err != nil || tokenString == "" {
		t.Errorf("Couldn't create token. Err: %v", err)
	}

	_, err = ValidateJWT(tokenString, "54321")
	if err == nil {
		t.Errorf("Validation failed. Should be rejected for wrong auth.")
	}
}

func TestGetBearerToken(t *testing.T) {
	headers := http.Header{}
	headers["Authorization"] = []string{"Bearer 12345"}
	tokenString, err := GetBearerToken(headers)
	if err != nil || tokenString != "12345" {
		t.Errorf("Failed to get Bearer token. Err: %v", err)
	}
}