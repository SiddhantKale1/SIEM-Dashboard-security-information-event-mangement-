package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel/siem-backend/internal/database"
	"github.com/sentinel/siem-backend/internal/models"
	"github.com/sentinel/siem-backend/internal/services"
)

type AgentHandler struct {
	store    *database.Store
	aiEngine *services.AIEngine
	netMgr   *services.NetworkManager
}

func NewAgentHandler(store *database.Store, aiEngine *services.AIEngine, netMgr *services.NetworkManager) *AgentHandler {
	return &AgentHandler{
		store:    store,
		aiEngine: aiEngine,
		netMgr:   netMgr,
	}
}

func (h *AgentHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	currentDevice := GetDeviceFromContext(r.Context())
	if currentDevice == nil {
		http.Error(w, `{"detail":"Device not authenticated"}`, http.StatusUnauthorized)
		return
	}

	var req models.HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"detail":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.DeviceID != currentDevice.DeviceID {
		http.Error(w, `{"detail":"Device ID mismatch"}`, http.StatusForbidden)
		return
	}

	now := time.Now().UTC()

	if req.Status == "offline" {
		currentDevice.Status = "offline"
		currentDevice.LastSeen = now
		_ = h.store.UpsertDevice(currentDevice)

		// Close active connection history sessions
		hist := h.store.GetConnectionHistory()
		for i := range hist {
			if hist[i].DeviceID == currentDevice.DeviceID && hist[i].Status == "active" {
				hist[i].Status = "closed"
				hist[i].DisconnectedAt = &now
				hist[i].TerminationReason = "device_shutdown"
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "offline",
			"server_time": now.Format(time.RFC3339),
		})
		return
	}

	currentDevice.Status = "online"
	currentDevice.LastSeen = now
	_ = h.store.UpsertDevice(currentDevice)

	h.netMgr.RecordConnectionEvent(
		currentDevice.DeviceID,
		currentDevice.Hostname,
		currentDevice.IPAddress,
		currentDevice.MACAddress,
		currentDevice.OS,
		"connected",
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "ok",
		"server_time": now.Format(time.RFC3339),
		"policies": map[string]interface{}{
			"blocked_domains": []string{},
		},
	})
}

func (h *AgentHandler) ReceiveLogs(w http.ResponseWriter, r *http.Request) {
	currentDevice := GetDeviceFromContext(r.Context())
	if currentDevice == nil {
		http.Error(w, `{"detail":"Device not authenticated"}`, http.StatusUnauthorized)
		return
	}

	var req models.LogsBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"detail":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.DeviceID != currentDevice.DeviceID {
		http.Error(w, `{"detail":"Device ID mismatch"}`, http.StatusForbidden)
		return
	}

	now := time.Now().UTC()
	logsToInsert := make([]models.Log, 0, len(req.Logs))

	for _, item := range req.Logs {
		t := now
		if str, ok := item.Timestamp.(string); ok && str != "" {
			if parsed, err := time.Parse(time.RFC3339, str); err == nil {
				t = parsed
			}
		}

		rawLogStr := ""
		if item.RawLog != nil {
			if s, ok := item.RawLog.(string); ok {
				rawLogStr = s
			} else {
				b, _ := json.Marshal(item.RawLog)
				rawLogStr = string(b)
			}
		}

		logModel := models.Log{
			ID:         uuid.New().String(),
			DeviceID:   currentDevice.DeviceID,
			Hostname:   currentDevice.Hostname,
			IPAddress:  currentDevice.IPAddress,
			OS:         item.OS,
			Timestamp:  t,
			IngestedAt: now,
			SourceType: item.SourceType,
			Source:     item.Source,
			EventID:    item.EventID,
			EventType:  item.EventType,
			Severity:   item.Severity,
			Message:    item.Message,
			RawLog:     rawLogStr,
		}
		if logModel.OS == "" {
			logModel.OS = currentDevice.OS
		}

		services.HumanizeLog(&logModel)
		logsToInsert = append(logsToInsert, logModel)
	}

	// Real-time AI Log Threat Analysis
	if len(logsToInsert) > 0 {
		h.aiEngine.AnalyzeLogs(
			currentDevice.DeviceID,
			currentDevice.Hostname,
			currentDevice.IPAddress,
			currentDevice.OS,
			logsToInsert,
		)
	}

	// Smart Persistence Filter
	logsToPersist := make([]models.Log, 0, len(logsToInsert))
	for _, l := range logsToInsert {
		if isLogWorthStoring(l) {
			logsToPersist = append(logsToPersist, l)
		}
	}

	if len(logsToPersist) > 0 {
		h.store.AddLogs(logsToPersist)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"processed": len(logsToInsert),
		"persisted": len(logsToPersist),
	})
}

func isLogWorthStoring(l models.Log) bool {
	sev := strings.ToLower(l.Severity)
	if sev == "warning" || sev == "error" || sev == "critical" || sev == "alert" || sev == "emergency" {
		return true
	}

	st := strings.ToLower(l.SourceType)
	src := strings.ToLower(l.Source)
	eid := strings.ToLower(l.EventID)
	msg := strings.ToLower(l.Message)

	if st == "network" || eid == "dns_query" || eid == "tcp_established" ||
		src == "dns_cache" || src == "kernel_socket" || src == "netstat" || src == "ss" || src == "firewall" {
		return true
	}
	if strings.Contains(src, "dns") || strings.Contains(msg, "domain") || strings.Contains(msg, "website") || strings.Contains(msg, "http") {
		return true
	}

	keywords := []string{
		"auth", "login", "logon", "failed", "failure", "passwd", "sudo",
		"su:", "sshd", "privilege", "shadow", "useradd", "userdel", "groupadd",
		"isolate", "quarantine", "threat", "firewall", "blocked", "malware",
		"attack", "brute", "tamper", "defender", "audit",
	}
	for _, k := range keywords {
		if strings.Contains(src, k) || strings.Contains(msg, k) {
			return true
		}
	}

	winEIDs := []string{"4624", "4625", "4672", "4720", "4726", "4738", "1102", "7045", "4697", "4698", "4702"}
	for _, we := range winEIDs {
		if eid == we {
			return true
		}
	}

	return false
}

func (h *AgentHandler) ReceiveMetrics(w http.ResponseWriter, r *http.Request) {
	currentDevice := GetDeviceFromContext(r.Context())
	if currentDevice == nil {
		http.Error(w, `{"detail":"Device not authenticated"}`, http.StatusUnauthorized)
		return
	}

	var req models.MetricsBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"detail":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.DeviceID != currentDevice.DeviceID {
		http.Error(w, `{"detail":"Device ID mismatch"}`, http.StatusForbidden)
		return
	}

	now := time.Now().UTC()
	metrics := make([]models.Metric, 0, len(req.Metrics))
	for _, m := range req.Metrics {
		t := now
		if str, ok := m.Timestamp.(string); ok && str != "" {
			if parsed, err := time.Parse(time.RFC3339, str); err == nil {
				t = parsed
			}
		}

		metrics = append(metrics, models.Metric{
			ID:             uuid.New().String(),
			DeviceID:       currentDevice.DeviceID,
			Timestamp:      t,
			CPUPercent:     m.CPUPercent,
			MemoryPercent:  m.MemoryPercent,
			DiskPercent:    m.DiskPercent,
			NetworkRXBytes: m.NetworkRXBytes,
			NetworkTXBytes: m.NetworkTXBytes,
		})
	}

	if len(metrics) > 0 {
		h.store.AddMetrics(metrics)
		h.aiEngine.AnalyzeMetrics(
			currentDevice.DeviceID,
			currentDevice.Hostname,
			currentDevice.IPAddress,
			currentDevice.OS,
			metrics,
		)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (h *AgentHandler) ReceiveProcesses(w http.ResponseWriter, r *http.Request) {
	currentDevice := GetDeviceFromContext(r.Context())
	if currentDevice == nil {
		http.Error(w, `{"detail":"Device not authenticated"}`, http.StatusUnauthorized)
		return
	}

	var req models.ProcessesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"detail":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.DeviceID != currentDevice.DeviceID {
		http.Error(w, `{"detail":"Device ID mismatch"}`, http.StatusForbidden)
		return
	}

	h.store.SetProcesses(currentDevice.DeviceID, req.Processes)
	h.aiEngine.AnalyzeProcesses(
		currentDevice.DeviceID,
		currentDevice.Hostname,
		currentDevice.IPAddress,
		currentDevice.OS,
		req.Processes,
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
