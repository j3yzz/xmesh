package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
)

type Post struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type CreatePostRequest struct {
	Content string `json:"content"`
}

var (
	db        *sql.DB
	jwtSecret []byte
)

func main() {
	var err error

	jwtSecretStr := os.Getenv("JWT_SECRET")
	if jwtSecretStr == "" {
		log.Fatal("JWT_SECRET is not set")
	}
	jwtSecret = []byte(jwtSecretStr)

	db, err = initDB()
	if err != nil {
		log.Fatalf("failed to init db: %v", err)
	}
	defer db.Close()

	if err := migrate(db); err != nil {
		log.Fatalf("failed to migrate db: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/ready", readyHandler)
	// /posts:
	//   - GET  -> list recent posts (global)
	//   - POST -> create new post for authenticated user
	mux.HandleFunc("/posts", postsHandler)
	// GET /posts/{userId} -> list all posts for a user (public)
	mux.HandleFunc("/posts/", listUserPostsHandler)

	port := getenv("PORT", "8585")
	addr := ":" + port
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("post-service listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit
	log.Print("shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("server shutdown: %v", err)
	}
	log.Print("server stopped")
}

func initDB() (*sql.DB, error) {
	host := getenv("DB_HOST", "xmesh-mysql")
	portStr := getenv("DB_PORT", "3306")
	user := getenv("DB_USER", "root")
	pass := getenv("DB_PASSWORD", "")
	dbName := getenv("DB_NAME", "post_svc")

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid DB_PORT: %w", err)
	}

	fmt.Println("user", user)
	fmt.Println("pass", pass)
	fmt.Println("host", host)
	fmt.Println("port", port)
	fmt.Println("dbName", dbName)

	cfg := mysql.Config{
		User:                 user,
		Passwd:               pass,
		Net:                  "tcp",
		Addr:                 fmt.Sprintf("%s:%d", host, port),
		DBName:               dbName,
		AllowNativePasswords: true,
		ParseTime:            true,
	}

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

func migrate(db *sql.DB) error {
	createTable := `
CREATE TABLE IF NOT EXISTS posts (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`
	_, err := db.Exec(createTable)
	return err
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func readyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if db == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	if err := db.Ping(); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type ctxKeyUserClaims struct{}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "invalid authorization header", http.StatusUnauthorized)
			return
		}

		tokenStr := parts[1]
		token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok {
			http.Error(w, "invalid token claims", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyUserClaims{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	claims, ok := r.Context().Value(ctxKeyUserClaims{}).(*Claims)
	if !ok || claims == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req CreatePostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		http.Error(w, "content is required", http.StatusBadRequest)
		return
	}

	res, err := db.Exec(`INSERT INTO posts (user_id, content) VALUES (?, ?)`, claims.UserID, req.Content)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	id, err := res.LastInsertId()
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	var post Post
	err = db.QueryRow(`SELECT id, user_id, content, created_at FROM posts WHERE id = ?`, id).
		Scan(&post.ID, &post.UserID, &post.Content, &post.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "post not found", http.StatusNotFound)
			return
		}
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, post)
}

func listUserPostsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Expect path: /posts/{userId}
	path := strings.TrimPrefix(r.URL.Path, "/posts/")
	if path == "" || strings.Contains(path, "/") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	userID, err := strconv.ParseInt(path, 10, 64)
	if err != nil || userID <= 0 {
		http.Error(w, "invalid user id", http.StatusBadRequest)
		return
	}

	rows, err := db.Query(
		`SELECT id, user_id, content, created_at FROM posts WHERE user_id = ? ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var p Post
		if err := rows.Scan(&p.ID, &p.UserID, &p.Content, &p.CreatedAt); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		posts = append(posts, p)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, posts)
}

// postsHandler routes /posts based on HTTP method:
//   - GET  -> listRecentPostsHandler (public, global feed style, limited to 30)
//   - POST -> createPostHandler (authenticated)
func postsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		listRecentPostsHandler(w, r)
	case http.MethodPost:
		authMiddleware(createPostHandler)(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// listRecentPostsHandler returns recent posts (global), ordered from newest to oldest.
// Supports optional ?limit and ?offset query parameters.
func listRecentPostsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()

	const (
		defaultLimit = 30
		maxLimit     = 30
	)

	limit := defaultLimit
	if v := query.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > maxLimit {
				n = maxLimit
			}
			limit = n
		}
	}

	offset := 0
	if v := query.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	rows, err := db.Query(
		`SELECT id, user_id, content, created_at FROM posts ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset,
	)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var p Post
		if err := rows.Scan(&p.ID, &p.UserID, &p.Content, &p.CreatedAt); err != nil {
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		posts = append(posts, p)
	}
	if err := rows.Err(); err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, posts)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
