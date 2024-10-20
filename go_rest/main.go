package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// Book struct (Model)
type Book struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Author string `json:"author"`
}

// User struct
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Initialize a slice to store books and users
var books []Book
var users []User                     // In-memory user storage
var jwtKey = []byte("my_secret_key") // Secret key for signing JWT tokens

// Upgrader is used to upgrade HTTP connections to WebSocket connections
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
}

// Generate JWT Token
func generateJWT(username string) (string, error) {
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
		Issuer:    username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// Login handler
func login(w http.ResponseWriter, r *http.Request) {
	var user User
	_ = json.NewDecoder(r.Body).Decode(&user)

	// Check if the user exists (in a real app, check a database)
	for _, u := range users {
		if u.Username == user.Username && u.Password == user.Password {
			token, err := generateJWT(user.Username)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"token": token})
			return
		}
	}
	http.Error(w, "Invalid credentials", http.StatusUnauthorized)
}

// Middleware to validate JWT Token
func validateJWT(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")

		if tokenString == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// Remove "Bearer " from token
		tokenString = tokenString[len("Bearer "):]

		claims := &jwt.StandardClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			log.Println("Token parsing error:", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			log.Println("Invalid token")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		log.Println("Token is valid")
		next.ServeHTTP(w, r)
	})
}

// Get all books
func getBooks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(books)
}

// Get a single book by ID
func getBook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r) // Get the URL parameters
	for _, item := range books {
		if item.ID == params["id"] {
			json.NewEncoder(w).Encode(item)
			return
		}
	}
	json.NewEncoder(w).Encode(&Book{})
}

// Create a new book
func createBook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var book Book
	_ = json.NewDecoder(r.Body).Decode(&book)
	book.ID = fmt.Sprintf("%d", len(books)+1) // Mock ID
	books = append(books, book)
	json.NewEncoder(w).Encode(book)
}

// Update a book by ID
func updateBook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	for index, item := range books {
		if item.ID == params["id"] {
			books = append(books[:index], books[index+1:]...)
			var book Book
			_ = json.NewDecoder(r.Body).Decode(&book)
			book.ID = params["id"]
			books = append(books, book)
			json.NewEncoder(w).Encode(book)
			return
		}
	}
	json.NewEncoder(w).Encode(books)
}

// Delete a book by ID
func deleteBook(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	for index, item := range books {
		if item.ID == params["id"] {
			books = append(books[:index], books[index+1:]...)
			break
		}
	}
	json.NewEncoder(w).Encode(books)
}

// WebSocket handler
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error while upgrading connection:", err)
		return
	}
	defer conn.Close()

	for {
		var msg string
		// err := conn.ReadMessage(&msg) // Read message from client
		if err != nil {
			log.Println("Error reading message:", err)
			break
		}

		log.Printf("Received message: %s\n", msg)
		err = conn.WriteMessage(websocket.TextMessage, []byte("Echo: "+msg)) // Echo back the message
		if err != nil {
			log.Println("Error writing message:", err)
			break
		}
	}
}

func main() {
	// Initialize the router
	r := mux.NewRouter()

	// Mock data - @TODO: Replace with DB
	users = append(users, User{Username: "user1", Password: "pass1"}) // Mock user
	books = append(books, Book{ID: "1", Title: "The Catcher in the Rye", Author: "J.D. Salinger"})
	books = append(books, Book{ID: "2", Title: "To Kill a Mockingbird", Author: "Harper Lee"})

	// Route handlers & endpoints
	r.HandleFunc("/api/login", login).Methods("POST")

	// Protect book routes with JWT validation
	bookRouter := r.PathPrefix("/api/books").Subrouter()
	bookRouter.Use(validateJWT) // Apply JWT validation middleware
	bookRouter.HandleFunc("", getBooks).Methods("GET")
	bookRouter.HandleFunc("/{id}", getBook).Methods("GET")
	bookRouter.HandleFunc("", createBook).Methods("POST")
	bookRouter.HandleFunc("/{id}", updateBook).Methods("PUT")
	bookRouter.HandleFunc("/{id}", deleteBook).Methods("DELETE")

	// WebSocket route
	r.HandleFunc("/ws", handleWebSocket) // WebSocket route

	// Start the server
	log.Fatal(http.ListenAndServe(":8000", r))
}
