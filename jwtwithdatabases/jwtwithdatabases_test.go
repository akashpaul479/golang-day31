package jwtwithdatabases_test

import (
	"bytes"
	"encoding/json"
	"jwt/jwtwithdatabases"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestLogin(t *testing.T) {
	tests := []struct {
		name     string // description of this test case
		creds    jwtwithdatabases.Credentials
		willpass bool
	}{
		{
			name: "valid credentials",
			creds: jwtwithdatabases.Credentials{
				Email:    "akash@gmail.com",
				Password: "Akash@123",
			},
			willpass: true,
		},
		{
			name: "invalid credentials",
			creds: jwtwithdatabases.Credentials{
				Email:    "wrong@gmail.com",
				Password: "Wrong",
			},
			willpass: false,
		},
		{
			name: "empty password",
			creds: jwtwithdatabases.Credentials{
				Email:    "akash@gmail.com",
				Password: "",
			},
			willpass: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userBody, err := json.Marshal(tt.creds)
			if err != nil {
				panic(err)
			}
			buffer := bytes.NewBuffer(userBody)
			r := httptest.NewRequest(http.MethodPost, "/login", buffer)
			w := httptest.NewRecorder()

			jwtwithdatabases.Login(w, r)

			if tt.willpass {
				if w.Code != http.StatusOK {
					t.Fatalf("Expected ok status , got %d", w.Code)
				}
				var resp map[string]string
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("Failed to decode response: %v", err)
				}
				if _, ok := resp["token"]; !ok {
					t.Fatalf("Expected token in response , got %v", resp)
				}

			} else {
				if w.Code == http.StatusOK {
					t.Fatalf("Expected not ok status , got %d", w.Code)
				}
			}
		})
	}
}

func TestJWTMiddleware(t *testing.T) {
	validToken := func() string {
		expiration := time.Now().Add(30 * time.Minute)
		claims := &jwtwithdatabases.Claims{
			Email: "akash@gmail.com",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expiration),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString(jwtwithdatabases.SecretKey)
		return tokenString
	}()

	tests := []struct {
		name       string // description of this test case
		authHeader string
		willpass   bool
	}{
		{
			name:       "valid Token",
			authHeader: "Bearer " + validToken,
			willpass:   true,
		},
		{
			name:       "Invalid Token",
			authHeader: "Bearer invalid",
			willpass:   false,
		},
		{
			name:       "missing token",
			authHeader: "",
			willpass:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("OK"))
			})

			handler := jwtwithdatabases.JWTMiddleware(nextHandler)

			r := httptest.NewRequest(http.MethodGet, "/api/users/1", nil)
			if tt.authHeader != "" {
				r.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, r)

			if tt.willpass {
				if w.Code != http.StatusOK {
					t.Fatalf("Expected ok status , got %d", w.Code)
				}
			} else {
				if w.Code == http.StatusOK {
					t.Fatalf("Expected not ok status , got %d", w.Code)
				}

			}
		})
	}
}
