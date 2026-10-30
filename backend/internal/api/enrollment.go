package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/sentinel/siem-backend/internal/auth"
	"github.com/sentinel/siem-backend/internal/config"
	"github.com/sentinel/siem-backend/internal/database"
	"github.com/sentinel/siem-backend/internal/models"
	"github.com/sentinel/siem-backend/internal/scripts"
	"github.com/sentinel/siem-backend/internal/services"
)

type EnrollmentHandler struct {
	store  *database.Store
	cfg    *config.Config
	netMgr *services.NetworkManager
}

func NewEnrollmentHandler(store *database.Store, cfg *config.Config, netMgr *services.NetworkManager) *EnrollmentHandler {
	return &EnrollmentHandler{
		store:  store,
		cfg:    cfg,
		netMgr: netMgr,
	}
}

func randomTokenSegment(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[num.Int64()]
	}
	return string(b)
}

func GenerateEnrollmentToken() string {
	return fmt.Sprintf("ENROLL-%s-%s", randomTokenSegment(4), randomTokenSegment(4))
}

func (h *EnrollmentHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	if err := services.RequireNotViewer(user, "create enrollment tokens"); err != nil {
		http.Error(w, fmt.Sprintf(`{"detail":"%s"}`, err.Error()), http.StatusForbidden)
		return
	}

	reusable := true
	if r.URL.Query().Get("reusable") == "false" {
		reusable = false
	}

	daysValid := 30
	if d := r.URL.Query().Get("days_valid"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed >= 1 && parsed <= 365 {
			daysValid = parsed
		}
	}

	tokenStr := strings.TrimSpace(r.URL.Query().Get("specific_token"))
	if tokenStr == "" {
		tokenStr = GenerateEnrollmentToken()
	}

	tok, err := h.store.CreateToken(tokenStr, user.Username, reusable, daysValid)
	if err != nil {
		http.Error(w, `{"detail":"Failed to generate enrollment token"}`, http.StatusInternalServerError)
		return
	}

	serverURL := h.cfg.ServerPublicURL
	if serverURL == "" {
		proto := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			proto = "https"
		}
		host := r.Host
		if host != "" && !strings.Contains(host, "localhost") && !strings.Contains(host, "127.0.0.1") {
			serverURL = fmt.Sprintf("%s://%s", proto, host)
		} else {
			netInfo := h.netMgr.GetLocalNetworkInfo()
			serverURL = fmt.Sprintf("http://%s:8000", netInfo.ServerIP)
		}
	}
	serverURL = strings.TrimRight(serverURL, "/")

	linuxCmd := fmt.Sprintf(`curl -sSL "%s/api/v1/enrollment/install.sh" | sudo bash -s -- --server "%s" --token "%s"`, serverURL, serverURL, tokenStr)
	windowsCmd := fmt.Sprintf(`powershell -ExecutionPolicy Bypass -Command "irm '%s/api/v1/enrollment/install.ps1?token=%s&server=%s' | iex"`, serverURL, tokenStr, serverURL)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      tokenStr,
		"expires_at": tok.ExpiresAt.Format(time.RFC3339),
		"reusable":   tok.Reusable,
		"server_url": serverURL,
		"install_commands": map[string]string{
			"linux":   linuxCmd,
			"windows": windowsCmd,
		},
	})
}

func (h *EnrollmentHandler) RegisterDevice(w http.ResponseWriter, r *http.Request) {
	var req models.DeviceRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"detail":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	tokenStr := strings.TrimSpace(req.Token)
	if tokenStr == "" {
		http.Error(w, `{"detail":"Invalid or expired enrollment token"}`, http.StatusBadRequest)
		return
	}

	// Device registration ID
	deviceID := fmt.Sprintf("device-%s", uuid.New().String()[:8])

	tok, err := h.store.ValidateAndUseToken(tokenStr, deviceID)
	if err != nil {
		http.Error(w, `{"detail":"Invalid or expired enrollment token"}`, http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	netInfo := h.netMgr.GetLocalNetworkInfo()

	// Reuse existing device if matching MAC exists
	creator := tok.CreatedBy
	if creator == "" {
		creator = "admin"
	}

	allDevs := h.store.GetAllDevices()
	for _, d := range allDevs {
		if req.MACAddress != "" && d.MACAddress == req.MACAddress {
			deviceID = d.DeviceID
			break
		}
	}

	dev := &models.Device{
		ID:           uuid.New().String(),
		DeviceID:     deviceID,
		Hostname:     req.Hostname,
		IPAddress:    req.IPAddress,
		MACAddress:   req.MACAddress,
		OS:           req.OS,
		OSVersion:    req.OSVersion,
		AgentVersion: req.AgentVersion,
		Status:       "online",
		Subnet:       netInfo.Subnet,
		Owner:        creator,
		CreatedBy:    creator,
		LastSeen:     now,
		CreatedAt:    now,
		EnrolledAt:   now,
	}
	_ = h.store.UpsertDevice(dev)

	h.store.AddDeviceEvent(models.DeviceEvent{
		ID:        uuid.New().String(),
		DeviceID:  deviceID,
		Event:     "enrolled",
		Timestamp: now,
		Details:   fmt.Sprintf("Enrolled via token created by %s", creator),
	})

	h.netMgr.RecordConnectionEvent(
		deviceID,
		req.Hostname,
		req.IPAddress,
		req.MACAddress,
		req.OS,
		"connected",
	)

	// Issue 10-year device JWT
	deviceCred, err := auth.GenerateToken(deviceID, "device", deviceID, 3650*24*time.Hour)
	if err != nil {
		http.Error(w, `{"detail":"Failed to generate device credential"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(models.DeviceRegistrationResponse{
		DeviceID:         deviceID,
		DeviceCredential: deviceCred,
	})
}

func (h *EnrollmentHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	isAdmin := user.Role == "admin"
	allTokens := h.store.GetAllTokens()
	now := time.Now().UTC()

	result := make([]map[string]interface{}, 0)
	for _, t := range allTokens {
		if !isAdmin && t.CreatedBy != user.Username {
			continue
		}
		if now.After(t.ExpiresAt) {
			continue
		}

		result = append(result, map[string]interface{}{
			"id":            t.ID,
			"token_preview": t.TokenPreview,
			"created_by":    t.CreatedBy,
			"reusable":      t.Reusable,
			"use_count":     t.UseCount,
			"created_at":    t.CreatedAt.Format(time.RFC3339),
			"expires_at":    t.ExpiresAt.Format(time.RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (h *EnrollmentHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	tokenID := chi.URLParam(r, "token_id")
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	allTokens := h.store.GetAllTokens()
	var target *models.EnrollmentToken
	for _, t := range allTokens {
		if t.ID == tokenID {
			target = t
			break
		}
	}

	if target == nil {
		http.Error(w, `{"detail":"Token not found"}`, http.StatusNotFound)
		return
	}

	if user.Role != "admin" && target.CreatedBy != user.Username {
		http.Error(w, `{"detail":"Permission denied: You can only revoke enrollment tokens that you created"}`, http.StatusForbidden)
		return
	}

	h.store.RevokeToken(tokenID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Token revoked"})
}

func (h *EnrollmentHandler) ServeLinuxInstaller(w http.ResponseWriter, r *http.Request) {
	netInfo := h.netMgr.GetLocalNetworkInfo()
	token := r.URL.Query().Get("token")
	server := r.URL.Query().Get("server")
	if server == "" {
		server = fmt.Sprintf("http://%s:8000", netInfo.ServerIP)
	}

	script := scripts.GenerateLinuxInstaller(server, token)
	w.Header().Set("Content-Type", "text/x-shellscript")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(script))
}

func (h *EnrollmentHandler) ServeWindowsInstaller(w http.ResponseWriter, r *http.Request) {
	netInfo := h.netMgr.GetLocalNetworkInfo()
	token := r.URL.Query().Get("token")
	server := r.URL.Query().Get("server")
	if server == "" {
		server = fmt.Sprintf("http://%s:8000", netInfo.ServerIP)
	}

	script := scripts.GenerateWindowsInstaller(server, token)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(script))
}

func (h *EnrollmentHandler) ServeAgentPy(w http.ResponseWriter, r *http.Request) {
	source, err := scripts.ReadUniversalAgentSource()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"detail":"Failed to read agent source: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/x-python")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(source))
}
