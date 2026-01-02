package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

//go:embed static
var staticFiles embed.FS

const (
	dataFile    = "users.json"
	sessionDays = 7
)

type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type UserStore struct {
	Users map[string]User `json:"users"`
	mu    sync.RWMutex
}

type Session struct {
	Token     string
	Username  string
	ExpiresAt time.Time
}

type SessionStore struct {
	sessions map[string]Session
	mu       sync.RWMutex
}

var (
	userStore    *UserStore
	sessionStore *SessionStore
	proxyPort    int
	dataDir      string
	hostname     string
	rootPassword string
)

func main() {
	listenPort := flag.Int("port", 443, "Port to listen on")
	flag.IntVar(&proxyPort, "proxy-port", 3000, "Localhost port to proxy to")
	flag.StringVar(&hostname, "hostname", "", "Host name for Let's Encrypt certificate")
	flag.StringVar(&dataDir, "data-dir", ".", "Directory to store user data")
	flag.StringVar(&rootPassword, "root-password", "", "Initial password for 'root' user (required if users.json is missing)")
	flag.Parse()

	if hostname == "" {
		log.Println("Warning: -hostname not provided. SSL certificate will not be obtained automatically via Let's Encrypt.")
	}

	userStore = &UserStore{
		Users: make(map[string]User),
	}
	sessionStore = &SessionStore{
		sessions: make(map[string]Session),
	}

	if err := userStore.Load(); err != nil {
		if rootPassword == "" {
			log.Fatal("Error: No existing user data found and -root-password flag not provided. " +
				"You must provide an initial root password for the first run.")
		}
		log.Printf("No existing user data, creating default user 'root'")
		if err := userStore.CreateUser("root", rootPassword); err != nil {
			log.Fatal("Failed to create default user:", err)
		}
	}

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal("Failed to load static files:", err)
	}
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	http.HandleFunc("/login", loginPageHandler)
	http.HandleFunc("/api/login", apiLoginHandler)
	http.HandleFunc("/api/logout", apiLogoutHandler)
	http.HandleFunc("/admin", authMiddleware(adminPageHandler))
	http.HandleFunc("/api/admin/users", authMiddleware(adminAPIHandler))
	http.HandleFunc("/", authMiddleware(proxyHandler))

	addr := fmt.Sprintf(":%d", *listenPort)

	if hostname != "" {
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hostname),
			Cache:      autocert.DirCache("certs"),
		}

		server := &http.Server{
			Addr:      addr,
			TLSConfig: certManager.TLSConfig(),
		}

		log.Printf("Starting HTTPS server on https://%s%s", hostname, addr)
		log.Printf("Proxying authenticated requests to http://localhost:%d", proxyPort)

		// Serve HTTP for Let's Encrypt challenges
		go func() {
			log.Fatal(http.ListenAndServe(":80", certManager.HTTPHandler(nil)))
		}()

		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		log.Printf("Starting HTTP server on http://localhost%s (No hostname provided for HTTPS)", addr)
		log.Printf("Proxying authenticated requests to http://localhost:%d", proxyPort)
		log.Fatal(http.ListenAndServe(addr, nil))
	}
}

func (us *UserStore) Load() error {
	us.mu.Lock()
	defer us.mu.Unlock()

	data, err := os.ReadFile(filepath.Join(dataDir, dataFile))
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &us.Users)
}

func (us *UserStore) save() error {
	data, err := json.MarshalIndent(us.Users, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(dataDir, dataFile), data, 0600)
}

func (us *UserStore) CreateUser(username, password string) error {
	us.mu.Lock()
	defer us.mu.Unlock()

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	us.Users[username] = User{
		Username:     username,
		PasswordHash: string(hash),
	}

	return us.save()
}

func (us *UserStore) Authenticate(username, password string) bool {
	us.mu.RLock()
	defer us.mu.RUnlock()

	user, exists := us.Users[username]
	if !exists {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	return err == nil
}

func (us *UserStore) DeleteUser(username string) error {
	us.mu.Lock()
	defer us.mu.Unlock()

	if username == "root" {
		return fmt.Errorf("cannot delete root user")
	}

	delete(us.Users, username)
	return us.save()
}

func (us *UserStore) ListUsers() []string {
	us.mu.RLock()
	defer us.mu.RUnlock()

	users := make([]string, 0, len(us.Users))
	for username := range us.Users {
		users = append(users, username)
	}
	return users
}

func (ss *SessionStore) Create(username string) string {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	ss.sessions[token] = Session{
		Token:     token,
		Username:  username,
		ExpiresAt: time.Now().Add(sessionDays * 24 * time.Hour),
	}

	return token
}

func (ss *SessionStore) Validate(token string) (string, bool) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	session, exists := ss.sessions[token]
	if !exists || time.Now().After(session.ExpiresAt) {
		return "", false
	}

	return session.Username, true
}

func (ss *SessionStore) Delete(token string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.sessions, token)
}

func getTokenFromRequest(r *http.Request) string {
	cookie, err := r.Cookie("auth_token")
	if err == nil {
		return cookie.Value
	}

	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	return ""
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := getTokenFromRequest(r)
		if token == "" {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		username, valid := sessionStore.Validate(token)
		if !valid {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		r.Header.Set("X-Authenticated-User", username)
		next(w, r)
	}
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	token := getTokenFromRequest(r)
	if token != "" {
		if _, valid := sessionStore.Validate(token); valid {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	content, err := staticFiles.ReadFile("static/login.html")
	if err != nil {
		http.Error(w, "Failed to load login page", http.StatusInternalServerError)
		log.Printf("Error loading login.html: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(content)
}

func apiLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if !userStore.Authenticate(creds.Username, creds.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	token := sessionStore.Create(creds.Username)

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   hostname != "", // Only secure if using HTTPS
		MaxAge:   sessionDays * 24 * 60 * 60,
	})

	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
		"user":  creds.Username,
	})
}

func apiLogoutHandler(w http.ResponseWriter, r *http.Request) {
	token := getTokenFromRequest(r)
	if token != "" {
		sessionStore.Delete(token)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "auth_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	w.WriteHeader(http.StatusOK)
}

func adminPageHandler(w http.ResponseWriter, r *http.Request) {
	content, err := staticFiles.ReadFile("static/admin.html")
	if err != nil {
		http.Error(w, "Failed to load admin page", http.StatusInternalServerError)
		log.Printf("Error loading admin.html: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Write(content)
}

func adminAPIHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users := userStore.ListUsers()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(users)

	case http.MethodPost:
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Username == "" || req.Password == "" {
			http.Error(w, "Username and password required", http.StatusBadRequest)
			return
		}

		if err := userStore.CreateUser(req.Username, req.Password); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)

	case http.MethodDelete:
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if err := userStore.DeleteUser(req.Username); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	target := fmt.Sprintf("http://localhost:%d", proxyPort)
	targetURL, err := url.Parse(target)
	if err != nil {
		http.Error(w, "Proxy configuration error", http.StatusInternalServerError)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		http.Error(w, fmt.Sprintf("Backend server unavailable (localhost:%d)", proxyPort), http.StatusBadGateway)
	}

	proxy.ServeHTTP(w, r)
}
