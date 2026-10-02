package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

//
// MODELS
//

type User struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
}

type Post struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	UserID int    `json:"user_id"`
}

//
// IN-MEMORY STORES
//
// We are using these temporarily so you can learn the
// authentication flow without waiting for PostgreSQL.
//

type UserStore struct {
	users  map[int]User
	nextID int
}

func NewUserStore() *UserStore {
	return &UserStore{
		users:  make(map[int]User),
		nextID: 1,
	}
}

func (s *UserStore) CreateUser(email, passwordHash string) User {
	user := User{
		ID:           s.nextID,
		Email:        email,
		PasswordHash: passwordHash,
	}

	s.users[user.ID] = user
	s.nextID++

	return user
}

func (s *UserStore) GetUserByEmail(email string) (User, bool) {
	for _, user := range s.users {
		if user.Email == email {
			return user, true
		}
	}

	return User{}, false
}

//
// POST STORE
//

type PostStore struct {
	posts  map[int]Post
	nextID int
}

func NewPostStore() *PostStore {
	return &PostStore{
		posts:  make(map[int]Post),
		nextID: 1,
	}
}

func (s *PostStore) Create(userID int, title, body string) Post {
	post := Post{
		ID:     s.nextID,
		Title:  title,
		Body:   body,
		UserID: userID,
	}

	s.posts[post.ID] = post
	s.nextID++

	return post
}

func (s *PostStore) Get(id int) (Post, bool) {
	post, ok := s.posts[id]
	return post, ok
}

func (s *PostStore) All() []Post {
	posts := []Post{}

	for _, post := range s.posts {
		posts = append(posts, post)
	}

	return posts
}

func (s *PostStore) Update(id int, title, body string) (Post, bool) {
	post, ok := s.posts[id]

	if !ok {
		return Post{}, false
	}

	post.Title = title
	post.Body = body

	s.posts[id] = post

	return post, true
}

func (s *PostStore) Delete(id int) bool {
	_, ok := s.posts[id]

	if !ok {
		return false
	}

	delete(s.posts, id)

	return true
}

//
// PASSWORD HASHING
//

func hashPassword(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(plain),
		bcrypt.DefaultCost,
	)

	return string(hash), err
}

func checkPassword(hash, plain string) bool {
	if err := bcrypt.CompareHashAndPassword(
		[]byte(hash),
		[]byte(plain),
	); err != nil {
		return false
	}

	return true
}

//
// JWT
//

var jwtSecret = []byte("change-me-in-production")

func generateToken(userID int) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	)

	return token.SignedString(jwtSecret)
}

//
// CONTEXT
//

type contextKey string

const userIDKey contextKey = "userID"

//
// JSON HELPERS
//

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{
		"error": message,
	})
}

//
// SIGNUP
//

func signup(userStore *UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var input struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		err := json.NewDecoder(r.Body).Decode(&input)

		if err != nil {
			writeError(
				w,
				http.StatusBadRequest,
				"invalid JSON",
			)
			return
		}

		if input.Email == "" || input.Password == "" {
			writeError(
				w,
				http.StatusBadRequest,
				"email and password are required",
			)
			return
		}

		// Check if email already exists.
		_, exists := userStore.GetUserByEmail(input.Email)

		if exists {
			writeError(
				w,
				http.StatusConflict,
				"email already in use",
			)
			return
		}

		// Hash password.
		hash, err := hashPassword(input.Password)

		if err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				"could not process password",
			)
			return
		}

		// Store user.
		user := userStore.CreateUser(
			input.Email,
			hash,
		)

		writeJSON(
			w,
			http.StatusCreated,
			user,
		)
	}
}

//
// LOGIN
//

func login(userStore *UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var input struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}

		err := json.NewDecoder(r.Body).Decode(&input)

		if err != nil {
			writeError(
				w,
				http.StatusUnauthorized,
				"invalid email or password",
			)
			return
		}

		// Find user.
		user, exists := userStore.GetUserByEmail(input.Email)

		if !exists {
			writeError(
				w,
				http.StatusUnauthorized,
				"invalid email or password",
			)
			return
		}

		// Check password.
		if !checkPassword(
			user.PasswordHash,
			input.Password,
		) {
			writeError(
				w,
				http.StatusUnauthorized,
				"invalid email or password",
			)
			return
		}

		// Generate JWT.
		token, err := generateToken(user.ID)

		if err != nil {
			writeError(
				w,
				http.StatusInternalServerError,
				"could not create token",
			)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			map[string]string{
				"token": token,
			},
		)
	}
}

//
// AUTH MIDDLEWARE
//

func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		header := r.Header.Get("Authorization")

		if !strings.HasPrefix(header, "Bearer ") {
			writeError(
				w,
				http.StatusUnauthorized,
				"missing or malformed token",
			)
			return
		}

		tokenStr := strings.TrimPrefix(
			header,
			"Bearer ",
		)

		token, err := jwt.Parse(
			tokenStr,
			func(t *jwt.Token) (interface{}, error) {

				// Make sure the token uses the expected
				// signing method.
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}

				return jwtSecret, nil
			},
		)

		if err != nil || !token.Valid {
			writeError(
				w,
				http.StatusUnauthorized,
				"invalid or expired token",
			)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)

		if !ok {
			writeError(
				w,
				http.StatusUnauthorized,
				"invalid token claims",
			)
			return
		}

		userIDValue, ok := claims["user_id"].(float64)

		if !ok {
			writeError(
				w,
				http.StatusUnauthorized,
				"invalid user id",
			)
			return
		}

		userID := int(userIDValue)

		// Put user ID into request context.
		ctx := context.WithValue(
			r.Context(),
			userIDKey,
			userID,
		)

		next.ServeHTTP(
			w,
			r.WithContext(ctx),
		)
	})
}

//
// CREATE POST
//

func createPost(postStore *PostStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		userID := r.Context().Value(userIDKey)

		if userID == nil {
			writeError(
				w,
				http.StatusUnauthorized,
				"unauthorized",
			)
			return
		}

		id := userID.(int)

		var input struct {
			Title string `json:"title"`
			Body  string `json:"body"`
		}

		err := json.NewDecoder(r.Body).Decode(&input)

		if err != nil {
			writeError(
				w,
				http.StatusBadRequest,
				"invalid JSON",
			)
			return
		}

		post := postStore.Create(
			id,
			input.Title,
			input.Body,
		)

		writeJSON(
			w,
			http.StatusCreated,
			post,
		)
	}
}

//
// GET ALL POSTS
//

func listPosts(postStore *PostStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		posts := postStore.All()

		writeJSON(
			w,
			http.StatusOK,
			posts,
		)
	}
}

//
// GET ONE POST
//

func getPost(postStore *PostStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		id, err := strconv.Atoi(
			chi.URLParam(r, "id"),
		)

		if err != nil {
			writeError(
				w,
				http.StatusBadRequest,
				"invalid id",
			)
			return
		}

		post, ok := postStore.Get(id)

		if !ok {
			writeError(
				w,
				http.StatusNotFound,
				"post not found",
			)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			post,
		)
	}
}

//
// UPDATE POST
//

func updatePost(postStore *PostStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		id, err := strconv.Atoi(
			chi.URLParam(r, "id"),
		)

		if err != nil {
			writeError(
				w,
				http.StatusBadRequest,
				"invalid id",
			)
			return
		}

		userID := r.Context().Value(userIDKey)

		if userID == nil {
			writeError(
				w,
				http.StatusUnauthorized,
				"unauthorized",
			)
			return
		}

		currentUserID := userID.(int)

		// Find post.
		existing, ok := postStore.Get(id)

		if !ok {
			writeError(
				w,
				http.StatusNotFound,
				"post not found",
			)
			return
		}

		// Ownership check.
		if existing.UserID != currentUserID {
			writeError(
				w,
				http.StatusForbidden,
				"you don't own this post",
			)
			return
		}

		var input struct {
			Title string `json:"title"`
			Body  string `json:"body"`
		}

		err = json.NewDecoder(r.Body).Decode(&input)

		if err != nil {
			writeError(
				w,
				http.StatusBadRequest,
				"invalid JSON",
			)
			return
		}

		post, ok := postStore.Update(
			id,
			input.Title,
			input.Body,
		)

		if !ok {
			writeError(
				w,
				http.StatusNotFound,
				"post not found",
			)
			return
		}

		writeJSON(
			w,
			http.StatusOK,
			post,
		)
	}
}

//
// DELETE POST
//

func deletePost(postStore *PostStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		id, err := strconv.Atoi(
			chi.URLParam(r, "id"),
		)

		if err != nil {
			writeError(
				w,
				http.StatusBadRequest,
				"invalid id",
			)
			return
		}

		userID := r.Context().Value(userIDKey)

		if userID == nil {
			writeError(
				w,
				http.StatusUnauthorized,
				"unauthorized",
			)
			return
		}

		currentUserID := userID.(int)

		// Find post.
		post, ok := postStore.Get(id)

		if !ok {
			writeError(
				w,
				http.StatusNotFound,
				"post not found",
			)
			return
		}

		// Ownership check.
		if post.UserID != currentUserID {
			writeError(
				w,
				http.StatusForbidden,
				"you don't own this post",
			)
			return
		}

		postStore.Delete(id)

		writeJSON(
			w,
			http.StatusOK,
			map[string]string{
				"message": "post deleted",
			},
		)
	}
}

//
// MAIN
//

func main() {

	userStore := NewUserStore()
	postStore := NewPostStore()

	r := chi.NewRouter()

	// =========================
	// PUBLIC ROUTES
	// =========================

	r.Post("/signup", signup(userStore))

	r.Post("/login", login(userStore))

	r.Get("/posts", listPosts(postStore))

	r.Get("/posts/{id}", getPost(postStore))

	// =========================
	// PROTECTED ROUTES
	// =========================

	r.Group(func(protected chi.Router) {

		protected.Use(requireAuth)

		protected.Post(
			"/posts",
			createPost(postStore),
		)

		protected.Put(
			"/posts/{id}",
			updatePost(postStore),
		)

		protected.Delete(
			"/posts/{id}",
			deletePost(postStore),
		)
	})

	log.Println("server running on :8080")

	err := http.ListenAndServe(
		":8080",
		r,
	)

	if err != nil {
		log.Fatal(err)
	}
}
