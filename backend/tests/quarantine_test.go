package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sentinel/siem-backend/internal/models"
	"github.com/sentinel/siem-backend/internal/quarantine"
)

func TestQuarantineManagerInit(t *testing.T) {
	tests := []struct {
		url          string
		expectedHost string
		expectedPort int
	}{
		{"http://127.0.0.1:8000", "127.0.0.1", 8000},
		{"https://10.0.0.5:8443", "10.0.0.5", 8443},
		{"http://localhost:9000", "127.0.0.1", 9000},
		{"https://siem.corp.internal", "siem.corp.internal", 443},
		{"http://siem.corp.internal", "siem.corp.internal", 80},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			m := quarantine.NewManager(tt.url)
			status := m.Status()
			if status.SiemPort != tt.expectedPort {
				t.Fatalf("Expected port %d, got %d", tt.expectedPort, status.SiemPort)
			}
			if status.IsQuarantined {
				t.Fatalf("Expected manager to start non-quarantined")
			}
		})
	}
}

func TestQuarantineEnforceAndLift(t *testing.T) {
	m := quarantine.NewManager("http://127.0.0.1:8000")

	if m.IsQuarantined() {
		t.Fatalf("Expected IsQuarantined to be false initially")
	}

	// 1. Enforce
	err := m.Enforce()
	if err != nil {
		t.Fatalf("Enforce returned error: %v", err)
	}
	if !m.IsQuarantined() {
		t.Fatalf("Expected IsQuarantined to be true after Enforce")
	}

	status := m.Status()
	if status.QuarantinedAt.IsZero() {
		t.Fatalf("Expected QuarantinedAt timestamp to be set")
	}

	// Idempotent Enforce
	err = m.Enforce()
	if err != nil {
		t.Fatalf("Subsequent Enforce returned error: %v", err)
	}

	// 2. Lift
	err = m.Lift()
	if err != nil {
		t.Fatalf("Lift returned error: %v", err)
	}
	if m.IsQuarantined() {
		t.Fatalf("Expected IsQuarantined to be false after Lift")
	}

	status = m.Status()
	if status.RestoredAt.IsZero() {
		t.Fatalf("Expected RestoredAt timestamp to be set")
	}

	// Idempotent Lift
	err = m.Lift()
	if err != nil {
		t.Fatalf("Subsequent Lift returned error: %v", err)
	}
}

func TestQuarantineLifecycleEndToEnd(t *testing.T) {
	h := setupTestHarness(t)
	defer h.Teardown()

	// 1. Admin login
	loginBody := map[string]string{"username": "admin", "password": "admin"}
	w := h.Request("POST", "/api/v1/auth/login", loginBody, "")
	if w.Code != http.StatusOK {
		t.Fatalf("Admin login failed: %d body: %s", w.Code, w.Body.String())
	}
	var tokenRes models.TokenResponse
	_ = json.NewDecoder(w.Body).Decode(&tokenRes)
	adminToken := tokenRes.AccessToken

	// 2. Create enrollment token
	w = h.Request("POST", "/api/v1/enrollment/token?reusable=true&days_valid=30", nil, adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Generate token failed: %d body: %s", w.Code, w.Body.String())
	}
	var tokenGenRes map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&tokenGenRes)
	enrollmentToken := tokenGenRes["token"].(string)

	// 3. Register endpoint device
	regPayload := models.DeviceRegistrationRequest{
		Token:        enrollmentToken,
		Hostname:     "quarantine-worker-01",
		IPAddress:    "192.168.1.185",
		MACAddress:   "AA:BB:CC:DD:EE:77",
		OS:           "linux",
		OSVersion:    "Ubuntu 24.04 LTS",
		AgentVersion: "2.0.0-go-native",
	}
	bodyBytes, _ := json.Marshal(regPayload)
	req := httptest.NewRequest("POST", "/api/v1/enrollment/register", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.Router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Device registration failed: %d", w.Code)
	}

	var regResp models.DeviceRegistrationResponse
	_ = json.Unmarshal(w.Body.Bytes(), &regResp)
	deviceID := regResp.DeviceID
	deviceCred := regResp.DeviceCredential

	// 4. Initialize Agent Quarantine Manager
	qMgr := quarantine.NewManager("http://127.0.0.1:8000")

	// Helper to send agent heartbeat
	sendAgentHeartbeat := func() int {
		hbReq := models.HeartbeatRequest{
			DeviceID:  deviceID,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Status:    "online",
		}
		hbBytes, _ := json.Marshal(hbReq)
		r := httptest.NewRequest("POST", "/api/v1/agent/heartbeat", bytes.NewReader(hbBytes))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", deviceCred))
		rec := httptest.NewRecorder()
		h.Router.ServeHTTP(rec, r)

		if rec.Code == http.StatusForbidden && bytes.Contains(rec.Body.Bytes(), []byte("Device is isolated")) {
			if !qMgr.IsQuarantined() {
				_ = qMgr.Enforce()
			}
		} else if rec.Code == http.StatusOK {
			if qMgr.IsQuarantined() {
				_ = qMgr.Lift()
			}
		}
		return rec.Code
	}

	// 5. Initial heartbeat while online -> 200 OK
	code := sendAgentHeartbeat()
	if code != http.StatusOK {
		t.Fatalf("Expected 200 OK for online heartbeat, got %d", code)
	}
	if qMgr.IsQuarantined() {
		t.Fatalf("Expected agent not to be quarantined")
	}

	// 6. SOC Analyst isolates device
	w = h.Request("POST", fmt.Sprintf("/api/v1/devices/%s/isolate", deviceID), nil, adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Device isolation failed: %d", w.Code)
	}

	dev, ok := h.Store.GetDevice(deviceID)
	if !ok || dev.Status != "isolated" {
		t.Fatalf("Expected device status in DB to be isolated")
	}

	// 7. Next heartbeat cycle -> triggers surgical kernel quarantine
	code = sendAgentHeartbeat()
	if code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for quarantined heartbeat, got %d", code)
	}
	if !qMgr.IsQuarantined() {
		t.Fatalf("Expected agent to have enforced surgical quarantine")
	}

	// Verify LastSeen updated even during quarantine
	devAfterHB, _ := h.Store.GetDevice(deviceID)
	if devAfterHB.LastSeen.Before(dev.LastSeen) {
		t.Fatalf("Expected LastSeen to be updated during quarantine heartbeat")
	}

	// 8. SOC Analyst restores device
	w = h.Request("POST", fmt.Sprintf("/api/v1/devices/%s/restore", deviceID), nil, adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Device restore failed: %d", w.Code)
	}

	devRestored, _ := h.Store.GetDevice(deviceID)
	if devRestored.Status != "online" {
		t.Fatalf("Expected device status to be online after restore")
	}

	// 9. Subsequent heartbeat cycle -> agent automatically lifts quarantine
	code = sendAgentHeartbeat()
	if code != http.StatusOK {
		t.Fatalf("Expected 200 OK for restored heartbeat, got %d", code)
	}
	if qMgr.IsQuarantined() {
		t.Fatalf("Expected agent to have lifted surgical quarantine")
	}
}
