package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel/siem-backend/internal/auth"
	"github.com/sentinel/siem-backend/internal/database"
	"github.com/sentinel/siem-backend/internal/models"
)

type contextKey string

const (
	UserContextKey   contextKey = "current_user"
	DeviceContextKey contextKey = "current_device"
)

type AuthHandler struct {
	store *database.Store
}

func NewAuthHandler(store *database.Store) *AuthHandler {
	return &AuthHandler{store: store}
}

func (h *AuthHandler) AuthUserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := auth.ValidateToken(tokenStr)
		if err != nil {
			http.Error(w, `{"detail":"Could not validate credentials"}`, http.StatusUnauthorized)
			return
		}

		user, ok := h.store.GetUser(claims.Username)
		if !ok {
			http.Error(w, `{"detail":"User not found"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (h *AuthHandler) AuthDeviceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := auth.ValidateToken(tokenStr)
		if err != nil || claims.Role != "device" {
			http.Error(w, `{"detail":"Invalid device token"}`, http.StatusUnauthorized)
			return
		}

		deviceID := claims.DeviceID
		if deviceID == "" {
			deviceID = claims.Username
		}

		device, ok := h.store.GetDevice(deviceID)
		if !ok {
			http.Error(w, `{"detail":"Device not found"}`, http.StatusNotFound)
			return
		}

		// Strictly enforce device quarantine boundary
		if device.Status == "isolated" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"detail":"Device is isolated"}`))
			return
		}

		ctx := context.WithValue(r.Context(), DeviceContextKey, device)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetUserFromContext(ctx context.Context) *models.User {
	if u, ok := ctx.Value(UserContextKey).(*models.User); ok {
		return u
	}
	return nil
}

func GetDeviceFromContext(ctx context.Context) *models.Device {
	if d, ok := ctx.Value(DeviceContextKey).(*models.Device); ok {
		return d
	}
	return nil
}

type LoginJSONRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var username, password string

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var req LoginJSONRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			username = strings.TrimSpace(req.Username)
			password = req.Password
		}
	} else {
		_ = r.ParseForm()
		username = strings.TrimSpace(r.FormValue("username"))
		password = r.FormValue("password")
	}

	if username == "" || password == "" {
		http.Error(w, `{"detail":"Incorrect username or password"}`, http.StatusUnauthorized)
		return
	}

	user, ok := h.store.GetUser(username)
	if !ok && username == "admin" {
		// Auto-seed admin user if missing
		hash, _ := auth.HashPassword("admin")
		adminUser := &models.User{
			ID:                 uuid.New().String(),
			Username:           "admin",
			PasswordHash:       hash,
			Role:               "admin",
			MustChangePassword: false,
			CreatedAt:          time.Now().UTC(),
		}
		_ = h.store.CreateUser(adminUser)
		user = adminUser
		ok = true
	}

	if !ok || !auth.CheckPassword(password, user.PasswordHash) {
		http.Error(w, `{"detail":"Incorrect username or password"}`, http.StatusUnauthorized)
		return
	}

	now := time.Now().UTC()
	user.LastLogin = &now
	_ = h.store.UpdateUser(user)

	token, err := auth.GenerateToken(user.Username, user.Role, "", 60*time.Minute)
	if err != nil {
		http.Error(w, `{"detail":"Failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(models.TokenResponse{
		AccessToken: token,
		TokenType:   "bearer",
	})
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"detail":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	cleanUsername := strings.TrimSpace(req.Username)
	if cleanUsername == "" {
		http.Error(w, `{"detail":"Username cannot be empty"}`, http.StatusBadRequest)
		return
	}
	if len(cleanUsername) < 3 {
		http.Error(w, `{"detail":"Username must be at least 3 characters"}`, http.StatusBadRequest)
		return
	}
	if len(req.Password) < 6 {
		http.Error(w, `{"detail":"Password must be at least 6 characters"}`, http.StatusBadRequest)
		return
	}

	if _, exists := h.store.GetUser(cleanUsername); exists {
		http.Error(w, `{"detail":"Username already registered"}`, http.StatusBadRequest)
		return
	}

	role := strings.ToLower(strings.TrimSpace(req.Role))
	if role != "admin" && role != "analyst" && role != "viewer" {
		role = "analyst"
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, `{"detail":"Failed to hash password"}`, http.StatusInternalServerError)
		return
	}

	now := time.Now().UTC()
	newUser := &models.User{
		ID:                 uuid.New().String(),
		Username:           cleanUsername,
		PasswordHash:       hash,
		Role:               role,
		MustChangePassword: false,
		CreatedAt:          now,
		LastLogin:          &now,
	}

	if err := h.store.CreateUser(newUser); err != nil {
		http.Error(w, `{"detail":"Failed to create user"}`, http.StatusInternalServerError)
		return
	}

	token, err := auth.GenerateToken(cleanUsername, role, "", 60*time.Minute)
	if err != nil {
		http.Error(w, `{"detail":"Failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(models.TokenResponse{
		AccessToken: token,
		TokenType:   "bearer",
	})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(models.UserResponse{
		Username:           user.Username,
		Role:               user.Role,
		MustChangePassword: user.MustChangePassword,
	})
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	var req models.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"detail":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if !auth.CheckPassword(req.CurrentPassword, user.PasswordHash) {
		http.Error(w, `{"detail":"Current password is incorrect"}`, http.StatusBadRequest)
		return
	}

	if len(req.NewPassword) < 8 {
		http.Error(w, `{"detail":"New password must be at least 8 characters"}`, http.StatusBadRequest)
		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		http.Error(w, `{"detail":"Failed to hash password"}`, http.StatusInternalServerError)
		return
	}

	user.PasswordHash = newHash
	user.MustChangePassword = false
	_ = h.store.UpdateUser(user)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Password updated successfully"})
}
