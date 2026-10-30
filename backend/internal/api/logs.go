package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sentinel/siem-backend/internal/database"
	"github.com/sentinel/siem-backend/internal/models"
	"github.com/sentinel/siem-backend/internal/services"
)

type LogsHandler struct {
	store *database.Store
}

func NewLogsHandler(store *database.Store) *LogsHandler {
	return &LogsHandler{store: store}
}

func (h *LogsHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	visibleDeviceIDs := services.GetVisibleDeviceIDs(user, h.store)
	allLogs := h.store.GetAllLogs()

	now := time.Now().UTC()
	startOfToday := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	total := 0
	today := 0
	errors := 0
	warnings := 0

	for _, l := range allLogs {
		if visibleDeviceIDs != nil && !contains(visibleDeviceIDs, l.DeviceID) {
			continue
		}
		total++
		if l.Timestamp.After(startOfToday) {
			today++
		}
		sev := strings.ToLower(l.Severity)
		if sev == "error" || sev == "critical" {
			errors++
		} else if sev == "warning" {
			warnings++
		}
	}

	if today == 0 && total > 0 {
		today = total
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{
		"logs_today": today,
		"logs_total": total,
		"errors":     errors,
		"warnings":   warnings,
	})
}

func (h *LogsHandler) GetHourly(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	visibleDeviceIDs := services.GetVisibleDeviceIDs(user, h.store)
	allLogs := h.store.GetAllLogs()

	timeframe := r.URL.Query().Get("timeframe")
	now := time.Now().UTC()

	result := make([]map[string]interface{}, 0)

	if timeframe == "1h" || timeframe == "live" {
		for i := 11; i >= 0; i-- {
			slotEnd := now.Add(-time.Duration(i*5) * time.Minute)
			slotStart := slotEnd.Add(-5 * time.Minute)
			cnt := 0
			for _, l := range allLogs {
				if visibleDeviceIDs != nil && !contains(visibleDeviceIDs, l.DeviceID) {
					continue
				}
				if (l.Timestamp.Equal(slotStart) || l.Timestamp.After(slotStart)) && (l.Timestamp.Equal(slotEnd) || l.Timestamp.Before(slotEnd)) {
					cnt++
				}
			}
			result = append(result, map[string]interface{}{
				"time":  slotEnd.Format("15:04"),
				"count": cnt,
			})
		}
	} else if timeframe == "7d" {
		for i := 6; i >= 0; i-- {
			dayDt := now.AddDate(0, 0, -i)
			cnt := 0
			for _, l := range allLogs {
				if visibleDeviceIDs != nil && !contains(visibleDeviceIDs, l.DeviceID) {
					continue
				}
				if l.Timestamp.Year() == dayDt.Year() && l.Timestamp.YearDay() == dayDt.YearDay() {
					cnt++
				}
			}
			result = append(result, map[string]interface{}{
				"time":  dayDt.Format("Mon 02"),
				"count": cnt,
			})
		}
	} else { // default 24h
		buckets := make(map[int]int)
		for _, l := range allLogs {
			if visibleDeviceIDs != nil && !contains(visibleDeviceIDs, l.DeviceID) {
				continue
			}
			if l.Timestamp.After(now.Add(-24 * time.Hour)) {
				buckets[l.Timestamp.Hour()]++
			}
		}
		for offset := 23; offset >= 0; offset-- {
			hDt := now.Add(-time.Duration(offset) * time.Hour)
			result = append(result, map[string]interface{}{
				"time":  hDt.Format("15:00"),
				"count": buckets[hDt.Hour()],
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (h *LogsHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	visibleDeviceIDs := services.GetVisibleDeviceIDs(user, h.store)

	qDevID := r.URL.Query().Get("device_id")
	if qDevID != "" {
		if visibleDeviceIDs != nil && !contains(visibleDeviceIDs, qDevID) {
			http.Error(w, `{"detail":"Access denied: You do not have permission to view logs for this device"}`, http.StatusForbidden)
			return
		}
	}

	severity := r.URL.Query().Get("severity")
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("search")))
	policyViolationsOnly := r.URL.Query().Get("policy_violations_only") == "true"

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}

	allLogs := h.store.GetAllLogs()
	matched := make([]models.Log, 0)

	for i := len(allLogs) - 1; i >= 0; i-- {
		l := allLogs[i]

		if visibleDeviceIDs != nil && !contains(visibleDeviceIDs, l.DeviceID) {
			continue
		}
		if qDevID != "" && l.DeviceID != qDevID {
			continue
		}
		if severity != "" && severity != "all" && !strings.EqualFold(l.Severity, severity) {
			continue
		}

		services.HumanizeLog(&l)

		if policyViolationsOnly && !l.IsPolicyViolation {
			continue
		}

		if search != "" {
			combined := strings.ToLower(fmt.Sprintf("%s %s %s %s %s %s",
				l.Hostname, l.Message, l.Source, l.EventID, l.FriendlySummary, l.Category,
			))
			if !strings.Contains(combined, search) {
				continue
			}
		}

		matched = append(matched, l)
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
		"logs":  paginated,
		"page":  page,
		"limit": limit,
		"total": total,
		"pages": pages,
	})
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
