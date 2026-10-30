package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel/siem-backend/internal/database"
	"github.com/sentinel/siem-backend/internal/models"
	"github.com/sentinel/siem-backend/internal/services"
)

type NetworkHandler struct {
	store  *database.Store
	netMgr *services.NetworkManager
}

func NewNetworkHandler(store *database.Store, netMgr *services.NetworkManager) *NetworkHandler {
	return &NetworkHandler{
		store:  store,
		netMgr: netMgr,
	}
}

func (h *NetworkHandler) GetTraffic(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	netInfo := h.netMgr.GetLocalNetworkInfo()
	visibleDeviceIDs := services.GetVisibleDeviceIDs(user, h.store)
	allDevs := h.store.GetAllDevices()

	now := time.Now().UTC()
	cutoff := now.Add(-90 * time.Second)

	activeCount := 0
	totalManaged := 0

	for _, d := range allDevs {
		if visibleDeviceIDs != nil && !contains(visibleDeviceIDs, d.DeviceID) {
			continue
		}
		totalManaged++
		if d.LastSeen.After(cutoff) && h.netMgr.IsIPInSubnet(d.IPAddress, netInfo.Subnet) && d.Status != "isolated" {
			activeCount++
		}
	}

	allMetrics := h.store.Metrics
	var totalTX int64
	var totalRX int64
	for i := len(allMetrics) - 1; i >= 0 && i >= len(allMetrics)-50; i-- {
		m := allMetrics[i]
		if visibleDeviceIDs == nil || contains(visibleDeviceIDs, m.DeviceID) {
			totalTX += m.NetworkTXBytes
			totalRX += m.NetworkRXBytes
		}
	}

	historyCount := len(h.store.GetConnectionHistory())

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"network":                netInfo,
		"active_devices_count":   activeCount,
		"total_managed_devices":  totalManaged,
		"history_sessions_count": historyCount,
		"aggregate_tx_bytes":     totalTX,
		"aggregate_rx_bytes":     totalRX,
		"status":                 "HEALTHY",
	})
}

func (h *NetworkHandler) GetActiveDevices(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	netInfo := h.netMgr.GetLocalNetworkInfo()
	scan := r.URL.Query().Get("scan") == "true"

	if scan {
		if err := services.RequireAdmin(user, "trigger subnet discovery scans"); err != nil {
			http.Error(w, fmt.Sprintf(`{"detail":"%s"}`, err.Error()), http.StatusForbidden)
			return
		}

		arpNodes := h.netMgr.GetARPDevices(true)
		now := time.Now().UTC()
		for _, node := range arpNodes {
			existing, ok := h.store.GetDevice(node.MACAddress)
			if !ok {
				_ = h.store.UpsertDevice(&models.Device{
					ID:                  uuid.New().String(),
					DeviceID:            "",
					Hostname:            node.Hostname,
					IPAddress:           node.IPAddress,
					MACAddress:          node.MACAddress,
					OS:                  "unknown",
					Status:              "discovered",
					CurrentNetworkState: "discovered",
					Subnet:              netInfo.Subnet,
					Owner:               "admin",
					CreatedBy:           "admin",
					LastSeen:            now,
					CreatedAt:           now,
				})
			} else {
				_ = existing
			}
		}
	}

	allDevs := h.store.GetAllDevices()
	visibleDeviceIDs := services.GetVisibleDeviceIDs(user, h.store)
	now := time.Now().UTC()
	cutoff := now.Add(-90 * time.Second)

	activeList := make([]*models.Device, 0)
	for _, d := range allDevs {
		if visibleDeviceIDs != nil && !contains(visibleDeviceIDs, d.DeviceID) {
			continue
		}

		if d.Owner == "" {
			d.Owner = d.CreatedBy
		}
		if d.Owner == "" {
			d.Owner = "admin"
		}

		isOnline := d.LastSeen.After(cutoff)
		if d.Status == "isolated" {
			d.CurrentNetworkState = "isolated"
		} else if isOnline {
			d.CurrentNetworkState = "online"
			d.Status = "online"
		} else {
			d.CurrentNetworkState = "offline"
			if d.Status != "discovered" {
				d.Status = "offline"
			}
		}

		d.Subnet = netInfo.Subnet
		activeList = append(activeList, d)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"network": netInfo,
		"count":   len(activeList),
		"devices": activeList,
	})
}

func (h *NetworkHandler) GetHistory(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, `{"detail":"Not authenticated"}`, http.StatusUnauthorized)
		return
	}

	visibleDeviceIDs := services.GetVisibleDeviceIDs(user, h.store)
	qDevID := r.URL.Query().Get("device_id")
	if qDevID != "" {
		if visibleDeviceIDs != nil && !contains(visibleDeviceIDs, qDevID) {
			http.Error(w, `{"detail":"Access denied: You do not have permission to view connection history for this device"}`, http.StatusForbidden)
			return
		}
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}

	allHist := h.store.GetConnectionHistory()
	matched := make([]models.ConnectionHistory, 0)

	for i := len(allHist) - 1; i >= 0 && len(matched) < limit; i-- {
		entry := allHist[i]
		if visibleDeviceIDs != nil && !contains(visibleDeviceIDs, entry.DeviceID) {
			continue
		}
		if qDevID != "" && entry.DeviceID != qDevID {
			continue
		}
		matched = append(matched, entry)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"total":   len(matched),
		"history": matched,
	})
}
