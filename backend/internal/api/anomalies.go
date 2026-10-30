package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/sentinel/siem-backend/internal/database"
	"github.com/sentinel/siem-backend/internal/models"
	"github.com/sentinel/siem-backend/internal/services"
)

type AnomaliesHandler struct {
	store    *database.Store
	aiEngine *services.AIEngine
}

func NewAnomaliesHandler(store *database.Store, aiEngine *services.AIEngine) *AnomaliesHandler {
	return &AnomaliesHandler{
		store:    store,
		aiEngine: aiEngine,
	}
}

func (h *AnomaliesHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	visibleDeviceIDs := services.GetVisibleDeviceIDs(user, h.store)
	allAnom := h.store.GetAllAnomalies()

	userAnomalies := make([]*models.Anomaly, 0)
	total := 0
	active := 0
	critical := 0
	high := 0
	medium := 0
	resolved := 0

	for _, a := range allAnom {
		if visibleDeviceIDs != nil && !contains(visibleDeviceIDs, a.DeviceID) {
			continue
		}
		userAnomalies = append(userAnomalies, a)
		total++
		if a.Status == "active" {
			active++
			switch strings.ToLower(a.Severity) {
			case "critical":
				critical++
			case "high":
				high++
			case "medium":
				medium++
			}
		} else if a.Status == "resolved" {
			resolved++
		}
	}

	riskScore, posture, tacticCounts := h.aiEngine.CalculatePosture(userAnomalies)

	mitreDist := make([]map[string]interface{}, 0)
	for tactic, count := range tacticCounts {
		mitreDist = append(mitreDist, map[string]interface{}{
			"tactic": tactic,
			"count":  count,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"risk_score":         riskScore,
		"posture":            posture,
		"total_anomalies":    total,
		"active_threats":     active,
		"critical_threats":   critical,
		"high_threats":       high,
		"medium_threats":     medium,
		"resolved_threats":   resolved,
		"mitre_distribution": mitreDist,
	})
}

func (h *AnomaliesHandler) ListAnomalies(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	visibleDeviceIDs := services.GetVisibleDeviceIDs(user, h.store)

	qDevID := r.URL.Query().Get("device_id")
	if qDevID != "" {
		if visibleDeviceIDs != nil && !contains(visibleDeviceIDs, qDevID) {
			http.Error(w, `{"detail":"Access denied: You do not have permission to view anomalies for this device"}`, http.StatusForbidden)
			return
		}
	}

	status := r.URL.Query().Get("status")
	severity := r.URL.Query().Get("severity")

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	allAnom := h.store.GetAllAnomalies()
	matched := make([]*models.Anomaly, 0)

	for i := len(allAnom) - 1; i >= 0; i-- {
		a := allAnom[i]

		if visibleDeviceIDs != nil && !contains(visibleDeviceIDs, a.DeviceID) {
			continue
		}
		if qDevID != "" && a.DeviceID != qDevID {
			continue
		}
		if status != "" && status != "all" && !strings.EqualFold(a.Status, status) {
			continue
		}
		if severity != "" && severity != "all" && !strings.EqualFold(a.Severity, severity) {
			continue
		}

		// Enrich machine info from device if missing
		if dev, ok := h.store.GetDevice(a.DeviceID); ok {
			if a.IPAddress == "" || a.IPAddress == "127.0.0.1" || a.IPAddress == "None" {
				a.IPAddress = dev.IPAddress
			}
			if a.OS == "" || a.OS == "unknown" {
				a.OS = dev.OS
			}
			if a.Hostname == "" || a.Hostname == "unknown" {
				a.Hostname = dev.Hostname
			}
		}

		matched = append(matched, a)
	}

	total := len(matched)
	start := (page - 1) * limit
	end := start + limit
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	paginated := matched[start:end]
	pages := (total + limit - 1) / limit
	if pages == 0 {
		pages = 1
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"anomalies": paginated,
		"total":     total,
		"page":      page,
		"limit":     limit,
		"pages":     pages,
	})
}

func (h *AnomaliesHandler) GetAnomaly(w http.ResponseWriter, r *http.Request) {
	anomalyID := chi.URLParam(r, "anomaly_id")
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	anom, ok := h.store.GetAnomaly(anomalyID)
	if !ok {
		http.Error(w, `{"detail":"Anomaly not found"}`, http.StatusNotFound)
		return
	}

	if user.Role != "admin" {
		visible := services.GetVisibleDeviceIDs(user, h.store)
		if !contains(visible, anom.DeviceID) {
			http.Error(w, `{"detail":"Access denied: You do not have permission to view this incident"}`, http.StatusForbidden)
			return
		}
	}

	if dev, ok := h.store.GetDevice(anom.DeviceID); ok {
		if anom.IPAddress == "" || anom.IPAddress == "127.0.0.1" {
			anom.IPAddress = dev.IPAddress
		}
		if anom.OS == "" || anom.OS == "unknown" {
			anom.OS = dev.OS
		}
		if anom.Hostname == "" || anom.Hostname == "unknown" {
			anom.Hostname = dev.Hostname
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(anom)
}

func (h *AnomaliesHandler) ResolveAnomaly(w http.ResponseWriter, r *http.Request) {
	anomalyID := chi.URLParam(r, "anomaly_id")
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	if err := services.RequireNotViewer(user, "resolve anomalies"); err != nil {
		http.Error(w, fmt.Sprintf(`{"detail":"%s"}`, err.Error()), http.StatusForbidden)
		return
	}

	anom, ok := h.store.GetAnomaly(anomalyID)
	if !ok {
		http.Error(w, `{"detail":"Anomaly not found"}`, http.StatusNotFound)
		return
	}

	if user.Role != "admin" {
		visible := services.GetVisibleDeviceIDs(user, h.store)
		if !contains(visible, anom.DeviceID) {
			http.Error(w, `{"detail":"Access denied: You do not have permission to resolve incidents for this device"}`, http.StatusForbidden)
			return
		}
	}

	h.store.ResolveAnomaly(anomalyID, user.Username)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": "Incident marked as resolved",
	})
}
