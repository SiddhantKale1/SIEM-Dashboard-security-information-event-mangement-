package database

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel/siem-backend/internal/auth"
	"github.com/sentinel/siem-backend/internal/models"
)

type Store struct {
	mu                sync.RWMutex
	dataDir           string
	stateFile         string
	Users             map[string]*models.User              `json:"users"`             // keyed by username
	Devices           map[string]*models.Device            `json:"devices"`           // keyed by device_id
	Metrics           []models.Metric                      `json:"metrics"`
	Logs              []models.Log                         `json:"logs"`
	Processes         map[string]*models.ProcessSnapshot   `json:"processes"`         // keyed by device_id
	Anomalies         map[string]*models.Anomaly           `json:"anomalies"`         // keyed by anomaly_id
	ConnectionHistory []models.ConnectionHistory          `json:"connection_history"`
	DeviceEvents      []models.DeviceEvent                 `json:"device_events"`
	EnrollmentTokens  map[string]*models.EnrollmentToken   `json:"enrollment_tokens"` // keyed by id
}

func NewStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data dir: %w", err)
	}

	stateFile := filepath.Join(dataDir, "siem_state.json")
	store := &Store{
		dataDir:           dataDir,
		stateFile:         stateFile,
		Users:             make(map[string]*models.User),
		Devices:           make(map[string]*models.Device),
		Metrics:           make([]models.Metric, 0),
		Logs:              make([]models.Log, 0),
		Processes:         make(map[string]*models.ProcessSnapshot),
		Anomalies:         make(map[string]*models.Anomaly),
		ConnectionHistory: make([]models.ConnectionHistory, 0),
		DeviceEvents:      make([]models.DeviceEvent, 0),
		EnrollmentTokens:  make(map[string]*models.EnrollmentToken),
	}

	// Load existing state if available
	if data, err := os.ReadFile(stateFile); err == nil && len(data) > 0 {
		_ = json.Unmarshal(data, store)
		// Ensure non-nil maps
		if store.Users == nil { store.Users = make(map[string]*models.User) }
		if store.Devices == nil { store.Devices = make(map[string]*models.Device) }
		if store.Processes == nil { store.Processes = make(map[string]*models.ProcessSnapshot) }
		if store.Anomalies == nil { store.Anomalies = make(map[string]*models.Anomaly) }
		if store.EnrollmentTokens == nil { store.EnrollmentTokens = make(map[string]*models.EnrollmentToken) }
	}

	// Seed admin if not present
	if _, ok := store.Users["admin"]; !ok {
		adminPass := os.Getenv("ADMIN_INITIAL_PASSWORD")
		if adminPass == "" {
			adminPass = os.Getenv("ADMIN_PASSWORD")
		}
		if adminPass == "" {
			// Generate cryptographically secure initial password
			b := make([]byte, 10)
			_, _ = rand.Read(b)
			adminPass = hex.EncodeToString(b)
			log.Println("==================================================================")
			log.Println("[🔐 INITIAL ADMIN CREDENTIALS GENERATED]")
			log.Println("  Username: admin")
			log.Printf("  Password: %s\n", adminPass)
			log.Println("  (Set ADMIN_PASSWORD in environment to configure a static password)")
			log.Println("==================================================================")
		}
		adminHash, _ := auth.HashPassword(adminPass)
		store.Users["admin"] = &models.User{
			ID:                 uuid.New().String(),
			Username:           "admin",
			PasswordHash:       adminHash,
			Role:               "admin",
			MustChangePassword: false,
			CreatedAt:          time.Now().UTC(),
		}
		_ = store.saveLocked()
	} else if adminPass := os.Getenv("ADMIN_PASSWORD"); adminPass != "" {
		// Sync admin password if explicitly configured in environment
		adminHash, _ := auth.HashPassword(adminPass)
		store.Users["admin"].PasswordHash = adminHash
		_ = store.saveLocked()
	}

	return store, nil
}

func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.stateFile, data, 0644)
}

// User methods
func (s *Store) GetUser(username string) (*models.User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.Users[username]
	if !ok {
		return nil, false
	}
	// Return copy
	val := *u
	return &val, true
}

func (s *Store) CreateUser(u *models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.Users[u.Username]; exists {
		return fmt.Errorf("user already exists")
	}
	s.Users[u.Username] = u
	return s.saveLocked()
}

func (s *Store) UpdateUser(u *models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Users[u.Username] = u
	return s.saveLocked()
}

func (s *Store) DeleteUser(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Users, username)
	_ = s.saveLocked()
}

// Device methods
func (s *Store) GetAllDevices() []*models.Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	cutoff := now.Add(-90 * time.Second)

	list := make([]*models.Device, 0, len(s.Devices))
	for _, d := range s.Devices {
		if d.Status != "isolated" && d.Status != "discovered" {
			if d.LastSeen.After(cutoff) {
				d.Status = "online"
				d.CurrentNetworkState = "online"
			} else {
				d.Status = "offline"
				d.CurrentNetworkState = "offline"
			}
		} else if d.Status == "isolated" {
			d.CurrentNetworkState = "isolated"
		}
		cpy := *d
		list = append(list, &cpy)
	}
	return list
}

func (s *Store) GetDevice(deviceID string) (*models.Device, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.Devices[deviceID]
	if !ok {
		// Look up by ID or MAC
		for _, dev := range s.Devices {
			if dev.ID == deviceID || dev.MACAddress == deviceID {
				d = dev
				ok = true
				break
			}
		}
	}
	if !ok {
		return nil, false
	}

	// Update status dynamically
	if d.Status != "isolated" && d.Status != "discovered" {
		if d.LastSeen.After(time.Now().UTC().Add(-90 * time.Second)) {
			d.Status = "online"
		} else {
			d.Status = "offline"
		}
	}
	cpy := *d
	return &cpy, true
}

func (s *Store) UpsertDevice(d *models.Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Devices[d.DeviceID] = d
	return s.saveLocked()
}

func (s *Store) DeleteDevice(deviceID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	dev, ok := s.Devices[deviceID]
	if !ok {
		for id, d := range s.Devices {
			if d.ID == deviceID {
				dev = d
				deviceID = id
				ok = true
				break
			}
		}
	}
	if !ok {
		return false
	}

	delete(s.Devices, deviceID)

	// Cascade delete logs, metrics, events, connection history, anomalies
	newMetrics := make([]models.Metric, 0)
	for _, m := range s.Metrics {
		if m.DeviceID != deviceID {
			newMetrics = append(newMetrics, m)
		}
	}
	s.Metrics = newMetrics

	newLogs := make([]models.Log, 0)
	for _, l := range s.Logs {
		if l.DeviceID != deviceID {
			newLogs = append(newLogs, l)
		}
	}
	s.Logs = newLogs

	delete(s.Processes, deviceID)

	for aid, anom := range s.Anomalies {
		if anom.DeviceID == deviceID {
			delete(s.Anomalies, aid)
		}
	}

	newHist := make([]models.ConnectionHistory, 0)
	for _, h := range s.ConnectionHistory {
		if h.DeviceID != deviceID && (dev.IPAddress == "" || h.IPAddress != dev.IPAddress) {
			newHist = append(newHist, h)
		}
	}
	s.ConnectionHistory = newHist

	newEvts := make([]models.DeviceEvent, 0)
	for _, e := range s.DeviceEvents {
		if e.DeviceID != deviceID {
			newEvts = append(newEvts, e)
		}
	}
	s.DeviceEvents = newEvts

	_ = s.saveLocked()
	return true
}

// Metrics methods
func (s *Store) AddMetrics(metrics []models.Metric) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Metrics = append(s.Metrics, metrics...)
	// Keep last 10,000 metrics in memory
	if len(s.Metrics) > 10000 {
		s.Metrics = s.Metrics[len(s.Metrics)-10000:]
	}
	_ = s.saveLocked()
}

func (s *Store) GetDeviceMetrics(deviceID string, limit int) []models.Metric {
	s.mu.RLock()
	defer s.mu.RUnlock()
	matches := make([]models.Metric, 0)
	for i := len(s.Metrics) - 1; i >= 0 && len(matches) < limit; i-- {
		if s.Metrics[i].DeviceID == deviceID {
			matches = append(matches, s.Metrics[i])
		}
	}
	// Reverse to ascending order
	for i, j := 0, len(matches)-1; i < j; i, j = i+1, j-1 {
		matches[i], matches[j] = matches[j], matches[i]
	}
	return matches
}

// Logs methods
func (s *Store) AddLogs(logs []models.Log) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Logs = append(s.Logs, logs...)
	if len(s.Logs) > 50000 {
		s.Logs = s.Logs[len(s.Logs)-50000:]
	}
	_ = s.saveLocked()
}

func (s *Store) GetAllLogs() []models.Log {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]models.Log, len(s.Logs))
	copy(cp, s.Logs)
	return cp
}

// Processes methods
func (s *Store) SetProcesses(deviceID string, procs []models.Process) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Processes[deviceID] = &models.ProcessSnapshot{
		ID:        uuid.New().String(),
		DeviceID:  deviceID,
		Timestamp: time.Now().UTC(),
		Processes: procs,
	}
	_ = s.saveLocked()
}

func (s *Store) GetProcesses(deviceID string) (*models.ProcessSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.Processes[deviceID]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

// Anomalies methods
func (s *Store) AddAnomaly(a *models.Anomaly) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Anomalies[a.ID] = a
	_ = s.saveLocked()
}

func (s *Store) GetAnomaly(anomalyID string) (*models.Anomaly, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.Anomalies[anomalyID]
	if !ok {
		for _, item := range s.Anomalies {
			if item.ID == anomalyID {
				a = item
				ok = true
				break
			}
		}
	}
	if !ok {
		return nil, false
	}
	cp := *a
	return &cp, true
}

func (s *Store) GetAllAnomalies() []*models.Anomaly {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*models.Anomaly, 0, len(s.Anomalies))
	for _, a := range s.Anomalies {
		cp := *a
		list = append(list, &cp)
	}
	return list
}

func (s *Store) ResolveAnomaly(anomalyID, resolvedBy string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Anomalies[anomalyID]
	if !ok {
		for _, item := range s.Anomalies {
			if item.ID == anomalyID {
				a = item
				ok = true
				break
			}
		}
	}
	if !ok {
		return false
	}
	now := time.Now().UTC()
	a.Status = "resolved"
	a.ResolvedAt = &now
	a.ResolvedBy = resolvedBy
	a.UpdatedAt = now
	_ = s.saveLocked()
	return true
}

// Connection History methods
func (s *Store) AddConnectionHistory(entry models.ConnectionHistory) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ConnectionHistory = append(s.ConnectionHistory, entry)
	if len(s.ConnectionHistory) > 5000 {
		s.ConnectionHistory = s.ConnectionHistory[len(s.ConnectionHistory)-5000:]
	}
	_ = s.saveLocked()
}

func (s *Store) GetConnectionHistory() []models.ConnectionHistory {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]models.ConnectionHistory, len(s.ConnectionHistory))
	copy(cp, s.ConnectionHistory)
	return cp
}

// Device Events methods
func (s *Store) AddDeviceEvent(evt models.DeviceEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DeviceEvents = append(s.DeviceEvents, evt)
	_ = s.saveLocked()
}

func (s *Store) GetDeviceEvents(deviceID string) []models.DeviceEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	matches := make([]models.DeviceEvent, 0)
	for i := len(s.DeviceEvents) - 1; i >= 0; i-- {
		if s.DeviceEvents[i].DeviceID == deviceID {
			matches = append(matches, s.DeviceEvents[i])
		}
	}
	return matches
}

// Enrollment Tokens
func (s *Store) CreateToken(tokenStr, createdBy string, reusable bool, daysValid int) (*models.EnrollmentToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := sha256.Sum256([]byte(tokenStr))
	hashHex := hex.EncodeToString(h[:])

	tok := &models.EnrollmentToken{
		ID:           uuid.New().String(),
		TokenHash:    hashHex,
		TokenPreview: tokenStr[:min(11, len(tokenStr))] + "...",
		CreatedBy:    createdBy,
		Reusable:     reusable,
		Used:         false,
		UseCount:     0,
		DeviceIDs:    make([]string, 0),
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().AddDate(0, 0, daysValid),
	}
	s.EnrollmentTokens[tok.ID] = tok
	_ = s.saveLocked()
	return tok, nil
}

func (s *Store) ValidateAndUseToken(rawToken string, deviceID string) (*models.EnrollmentToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := sha256.Sum256([]byte(rawToken))
	hashHex := hex.EncodeToString(h[:])

	now := time.Now().UTC()
	for _, tok := range s.EnrollmentTokens {
		if tok.TokenHash == hashHex {
			if now.After(tok.ExpiresAt) {
				return nil, fmt.Errorf("token expired")
			}
			if !tok.Reusable && tok.Used {
				return nil, fmt.Errorf("token already used")
			}
			tok.Used = true
			tok.UseCount++
			tok.DeviceIDs = append(tok.DeviceIDs, deviceID)
			_ = s.saveLocked()
			return tok, nil
		}
	}
	return nil, fmt.Errorf("invalid token")
}

func (s *Store) GetAllTokens() []*models.EnrollmentToken {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*models.EnrollmentToken, 0, len(s.EnrollmentTokens))
	for _, t := range s.EnrollmentTokens {
		cp := *t
		list = append(list, &cp)
	}
	return list
}

func (s *Store) RevokeToken(tokenID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.EnrollmentTokens[tokenID]
	if !ok {
		return false
	}
	t.ExpiresAt = time.Now().UTC().Add(-1 * time.Second)
	t.Used = true
	_ = s.saveLocked()
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
