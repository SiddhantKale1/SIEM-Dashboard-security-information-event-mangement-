package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/sentinel/siem-backend/internal/database"
	"github.com/sentinel/siem-backend/internal/models"
	"github.com/sentinel/siem-backend/internal/services"
)

type DevicesHandler struct {
	store *database.Store
}

func NewDevicesHandler(store *database.Store) *DevicesHandler {
	return &DevicesHandler{store: store}
}

func (h *DevicesHandler) GetDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	dev, err := services.VerifyDeviceAccess(deviceID, user, h.store)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, `{"detail":"Device not found"}`, http.StatusNotFound)
		} else {
			http.Error(w, `{"detail":"Access denied: You do not have permission to view or manage this endpoint"}`, http.StatusForbidden)
		}
		return
	}

	if dev.Owner == "" {
		dev.Owner = dev.CreatedBy
	}
	if dev.Owner == "" {
		dev.Owner = "admin"
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dev)
}

func (h *DevicesHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	if _, err := services.VerifyDeviceAccess(deviceID, user, h.store); err != nil {
		http.Error(w, `{"detail":"Access denied"}`, http.StatusForbidden)
		return
	}

	metrics := h.store.GetDeviceMetrics(deviceID, 20)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metrics)
}

func (h *DevicesHandler) IsolateDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	if err := services.RequireNotViewer(user, "quarantine endpoints"); err != nil {
		http.Error(w, fmt.Sprintf(`{"detail":"%s"}`, err.Error()), http.StatusForbidden)
		return
	}

	dev, err := services.VerifyDeviceAccess(deviceID, user, h.store)
	if err != nil {
		http.Error(w, `{"detail":"Device not found or access denied"}`, http.StatusNotFound)
		return
	}

	if dev.Status == "isolated" {
		http.Error(w, `{"detail":"Device is already isolated"}`, http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	dev.Status = "isolated"
	dev.IsolatedAt = &now
	_ = h.store.UpsertDevice(dev)

	h.store.AddDeviceEvent(models.DeviceEvent{
		ID:        uuid.New().String(),
		DeviceID:  dev.DeviceID,
		Event:     "isolated",
		Timestamp: now,
		Details:   fmt.Sprintf("Isolated by %s", user.Username),
		Actor:     user.Username,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "isolated",
		"device_id": dev.DeviceID,
	})
}

func (h *DevicesHandler) RestoreDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	if err := services.RequireNotViewer(user, "restore quarantined endpoints"); err != nil {
		http.Error(w, fmt.Sprintf(`{"detail":"%s"}`, err.Error()), http.StatusForbidden)
		return
	}

	dev, err := services.VerifyDeviceAccess(deviceID, user, h.store)
	if err != nil {
		http.Error(w, `{"detail":"Device not found or access denied"}`, http.StatusNotFound)
		return
	}

	if dev.Status != "isolated" {
		http.Error(w, `{"detail":"Device is not isolated"}`, http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	dev.Status = "online"
	dev.RestoredAt = &now
	_ = h.store.UpsertDevice(dev)

	h.store.AddDeviceEvent(models.DeviceEvent{
		ID:        uuid.New().String(),
		DeviceID:  dev.DeviceID,
		Event:     "restored",
		Timestamp: now,
		Details:   fmt.Sprintf("Access restored by %s", user.Username),
		Actor:     user.Username,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "online",
		"device_id": dev.DeviceID,
	})
}

func (h *DevicesHandler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	if err := services.RequireAdmin(user, "permanently delete monitored endpoints"); err != nil {
		http.Error(w, fmt.Sprintf(`{"detail":"%s"}`, err.Error()), http.StatusForbidden)
		return
	}

	dev, ok := h.store.GetDevice(deviceID)
	if !ok {
		http.Error(w, `{"detail":"Device not found"}`, http.StatusNotFound)
		return
	}

	hostname := dev.Hostname
	actualID := dev.DeviceID

	h.store.DeleteDevice(deviceID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "deleted",
		"device_id": actualID,
		"hostname":  hostname,
		"message":   fmt.Sprintf("Device '%s' and all its associated monitoring records have been permanently removed.", hostname),
	})
}

func (h *DevicesHandler) GetDeviceEvents(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	if _, err := services.VerifyDeviceAccess(deviceID, user, h.store); err != nil {
		http.Error(w, `{"detail":"Access denied"}`, http.StatusForbidden)
		return
	}

	events := h.store.GetDeviceEvents(deviceID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

func (h *DevicesHandler) GetDeviceSystemLogs(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	if _, err := services.VerifyDeviceAccess(deviceID, user, h.store); err != nil {
		http.Error(w, `{"detail":"Access denied"}`, http.StatusForbidden)
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	allLogs := h.store.GetAllLogs()
	matched := make([]models.Log, 0)
	for i := len(allLogs) - 1; i >= 0 && len(matched) < limit; i-- {
		if allLogs[i].DeviceID == deviceID {
			l := allLogs[i]
			services.HumanizeLog(&l)
			matched = append(matched, l)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(matched)
}

var (
	domainRegexA = regexp.MustCompile(`\[Domain:\s*([a-zA-Z0-9\-\.]+)\]`)
	domainRegexB = regexp.MustCompile(`https?://([a-zA-Z0-9\-\.]+)`)
	domainRegexC = regexp.MustCompile(`(?i)(?:Website / Domain Visited|Visited Website):\s*(?:https?://)?([a-zA-Z0-9\-\.]+)`)
	ipRegex      = regexp.MustCompile(`(?:Resolved IP|Remote IP):\s*([0-9\.]+)`)
)

func extractDomain(msg, raw string) (string, string) {
	var dom, resIP string

	if m := domainRegexA.FindStringSubmatch(msg); len(m) > 1 {
		dom = m[1]
	} else if m := domainRegexB.FindStringSubmatch(msg); len(m) > 1 {
		dom = m[1]
	} else if m := domainRegexC.FindStringSubmatch(msg); len(m) > 1 {
		dom = m[1]
	}

	if m := ipRegex.FindStringSubmatch(msg); len(m) > 1 {
		resIP = m[1]
	}

	dom = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(dom)), ".")
	if len(dom) >= 3 && strings.Contains(dom, ".") && !strings.Contains(dom, "in-addr.arpa") {
		return dom, resIP
	}
	return "", ""
}

type VisitedDomainItem struct {
	Domain     string    `json:"domain"`
	Timestamp  time.Time `json:"timestamp"`
	Source     string    `json:"source"`
	ResolvedIP string    `json:"resolved_ip"`
}

func (h *DevicesHandler) GetDeviceNetworkLogs(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	if _, err := services.VerifyDeviceAccess(deviceID, user, h.store); err != nil {
		http.Error(w, `{"detail":"Access denied"}`, http.StatusForbidden)
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	// 1. Connection history sessions
	allHist := h.store.GetConnectionHistory()
	sessions := make([]models.ConnectionHistory, 0)
	for i := len(allHist) - 1; i >= 0 && len(sessions) < 50; i-- {
		if allHist[i].DeviceID == deviceID {
			sessions = append(sessions, allHist[i])
		}
	}

	// 2. Visited domains & network logs
	allLogs := h.store.GetAllLogs()
	visitedDomains := make([]VisitedDomainItem, 0)
	seenDomains := make(map[string]bool)
	netLogs := make([]models.Log, 0)

	netKeywords := []string{
		"net", "firewall", "sshd", "ssh", "traffic", "socket", "wifi", "conn",
		"port", "packet", "flow", "ip", "tcp", "udp", "dns", "domain", "web",
		"url", "query", "youtube", "browser", "chrome", "edge", "firefox",
	}

	for i := len(allLogs) - 1; i >= 0; i-- {
		l := allLogs[i]
		if l.DeviceID != deviceID {
			continue
		}

		st := strings.ToLower(l.SourceType)
		src := strings.ToLower(l.Source)
		eid := strings.ToLower(l.EventID)
		msg := strings.ToLower(l.Message)

		isNet := st == "network" || eid == "dns_query" || eid == "web_visit" || eid == "tcp_established" ||
			src == "dns_cache" || src == "browser_network" || src == "kernel_socket" || src == "netstat" || src == "ss" || src == "firewall"

		if !isNet {
			for _, k := range netKeywords {
				if strings.Contains(src, k) || strings.Contains(msg, k) {
					isNet = true
					break
				}
			}
		}

		if isNet && len(netLogs) < limit {
			services.HumanizeLog(&l)
			netLogs = append(netLogs, l)
		}

		dom, resIP := extractDomain(l.Message, l.RawLog)
		if dom != "" && !seenDomains[dom] {
			seenDomains[dom] = true
			if resIP == "" {
				resIP = "—"
			}
			visitedDomains = append(visitedDomains, VisitedDomainItem{
				Domain:     dom,
				Timestamp:  l.Timestamp,
				Source:     l.Source,
				ResolvedIP: resIP,
			})
		}
	}

	// 3. Bandwidth metrics
	metrics := h.store.GetDeviceMetrics(deviceID, 30)

	// 4. Anomalies for this device
	allAnom := h.store.GetAllAnomalies()
	anomalies := make([]*models.Anomaly, 0)
	for i := len(allAnom) - 1; i >= 0 && len(anomalies) < 20; i-- {
		if allAnom[i].DeviceID == deviceID {
			anomalies = append(anomalies, allAnom[i])
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"device_id":         deviceID,
		"sessions":          sessions,
		"network_logs":      netLogs,
		"visited_domains":   visitedDomains,
		"bandwidth_metrics": metrics,
		"anomalies":         anomalies,
	})
}

func (h *DevicesHandler) GetProcesses(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	if _, err := services.VerifyDeviceAccess(deviceID, user, h.store); err != nil {
		http.Error(w, `{"detail":"Access denied"}`, http.StatusForbidden)
		return
	}

	procSnapshot, ok := h.store.GetProcesses(deviceID)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"device_id": deviceID,
			"processes": []models.Process{},
			"timestamp": nil,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(procSnapshot)
}
