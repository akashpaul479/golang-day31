package jwt2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

var SecretKey = []byte("Secret_Key")

// Models
type Student struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type Crenditals struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var students = []Student{}
var idCounter = 1

// JWT claims
type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// Login (generate JWT)
func Login(w http.ResponseWriter, r *http.Request) {
	var cred Crenditals
	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cred.Email != "akash@gmail.com" || cred.Password != "Akash123" {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	expiration := time.Now().Add(30 * time.Minute)
	claims := &Claims{
		Email: cred.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiration),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(SecretKey)

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})

}

// JWt middleware
func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}
		tokenstr := strings.TrimPrefix(auth, "Bearer ")

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenstr, claims, func(t *jwt.Token) (interface{}, error) {
			return SecretKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CRUD Handlers

// Create
func CreateStudent(w http.ResponseWriter, r *http.Request) {
	var student Student
	if err := json.NewDecoder(r.Body).Decode(&student); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	student.ID = idCounter
	idCounter++
	students = append(students, student)
	json.NewEncoder(w).Encode(student)
}

// Read all
func GetStudents(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(students)
}

// Read by ID
func GetStudent(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])

	for _, s := range students {
		if s.ID == id {
			json.NewEncoder(w).Encode(s)
			return
		}
	}
	http.Error(w, "student not found ", http.StatusNotFound)
}

// Update
func UpdateStudents(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])
	var Updated Student
	if err := json.NewDecoder(r.Body).Decode(&Updated); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for i, s := range students {
		if s.ID == id {
			students[i].Name = Updated.Name
			students[i].Email = Updated.Email
			json.NewEncoder(w).Encode(students[i])
			return
		}
	}
	http.Error(w, "student not found ", http.StatusNotFound)
}

// Delete
func DeleteStudents(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(mux.Vars(r)["id"])

	for i, s := range students {
		if s.ID == id {
			students = append(students[:i], students[i+1:]...)
			fmt.Fprintln(w, "Student deleted")
			return
		}
	}
	http.Error(w, "Student not found", http.StatusNotFound)
}

// Main func
func CrudRestApiWithJWT() {
	r := mux.NewRouter()

	// Public route
	r.HandleFunc("/login", Login).Methods("POST")

	// Protected route
	api := r.PathPrefix("/api").Subrouter()
	api.Use(JWTMiddleware)

	api.HandleFunc("/students", CreateStudent).Methods("POST")
	api.HandleFunc("/students", GetStudents).Methods("GET")
	api.HandleFunc("/students/{id}", GetStudent).Methods("GET")
	api.HandleFunc("/students/{id}", UpdateStudents).Methods("PUT")
	api.HandleFunc("/students/{id}", DeleteStudents).Methods("DELETE")

	fmt.Println("server running on port :8080")
	http.ListenAndServe(":8080", r)

}
