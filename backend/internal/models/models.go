package models

import "time"

type User struct {
	ID                 string     `json:"_id"`
	Username           string     `json:"username"`
	PasswordHash       string     `json:"password_hash,omitempty"`
	Role               string     `json:"role"`
	MustChangePassword bool       `json:"must_change_password"`
	CreatedAt          time.Time  `json:"created_at"`
	LastLogin          *time.Time `json:"last_login,omitempty"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type UserResponse struct {
	Username           string `json:"username"`
	Role               string `json:"role"`
	MustChangePassword bool   `json:"must_change_password"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Device struct {
	ID                  string     `json:"_id"`
	DeviceID            string     `json:"device_id"`
	Hostname            string     `json:"hostname"`
	IPAddress           string     `json:"ip_address"`
	MACAddress          string     `json:"mac_address"`
	OS                  string     `json:"os"`
	OSVersion           string     `json:"os_version"`
	AgentVersion        string     `json:"agent_version"`
	Status              string     `json:"status"` // online, offline, isolated, discovered
	CurrentNetworkState string     `json:"current_network_state,omitempty"`
	Subnet              string     `json:"subnet"`
	Owner               string     `json:"owner"`
	CreatedBy           string     `json:"created_by"`
	LastSeen            time.Time  `json:"last_seen"`
	CreatedAt           time.Time  `json:"created_at"`
	EnrolledAt          time.Time  `json:"enrolled_at"`
	IsolatedAt          *time.Time `json:"isolated_at,omitempty"`
	RestoredAt          *time.Time `json:"restored_at,omitempty"`
}

type Metric struct {
	ID             string    `json:"_id"`
	DeviceID       string    `json:"device_id"`
	Timestamp      time.Time `json:"timestamp"`
	CPUPercent     float64   `json:"cpu_percent"`
	MemoryPercent  float64   `json:"memory_percent"`
	DiskPercent    float64   `json:"disk_percent"`
	NetworkRXBytes int64     `json:"network_rx_bytes"`
	NetworkTXBytes int64     `json:"network_tx_bytes"`
}

type Log struct {
	ID                string    `json:"_id"`
	DeviceID          string    `json:"device_id"`
	Hostname          string    `json:"hostname"`
	IPAddress         string    `json:"ip_address,omitempty"`
	OS                string    `json:"os,omitempty"`
	Timestamp         time.Time `json:"timestamp"`
	IngestedAt        time.Time `json:"ingested_at,omitempty"`
	SourceType        string    `json:"source_type,omitempty"`
	Source            string    `json:"source"`
	EventID           string    `json:"event_id"`
	EventType         string    `json:"event_type,omitempty"`
	Severity          string    `json:"severity"` // information, warning, error, critical
	Message           string    `json:"message"`
	Category          string    `json:"category"`
	FriendlySummary   string    `json:"friendly_summary,omitempty"`
	IsPolicyViolation bool      `json:"is_policy_violation,omitempty"`
	RawLog            string    `json:"raw_log,omitempty"`
}

type Process struct {
	PID           int     `json:"pid"`
	Name          string  `json:"name"`
	Executable    string  `json:"executable,omitempty"`
	CommandLine   string  `json:"cmdline,omitempty"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	Username      string  `json:"username,omitempty"`
}

type ProcessSnapshot struct {
	ID        string    `json:"_id"`
	DeviceID  string    `json:"device_id"`
	Timestamp time.Time `json:"timestamp"`
	Processes []Process `json:"processes"`
}

type Anomaly struct {
	ID                string     `json:"_id"`
	DeviceID          string     `json:"device_id"`
	Hostname          string     `json:"hostname"`
	IPAddress         string     `json:"ip_address"`
	OS                string     `json:"os"`
	Title             string     `json:"title"`
	Severity          string     `json:"severity"` // critical, high, medium, low
	Status            string     `json:"status"`   // active, resolved
	Confidence        int        `json:"confidence"`
	MITREID           string     `json:"mitre_id"`
	MITRETechnique    string     `json:"mitre_technique"`
	MITRETactic       string     `json:"mitre_tactic"`
	MITREURL          string     `json:"mitre_url"`
	Summary           string     `json:"summary"`
	RootCause         string     `json:"root_cause"`
	Evidence          []string   `json:"evidence"`
	RecommendedAction string     `json:"recommended_action"`
	DetectedAt        time.Time  `json:"detected_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	ResolvedAt        *time.Time `json:"resolved_at,omitempty"`
	ResolvedBy        string     `json:"resolved_by,omitempty"`
}

type ConnectionHistory struct {
	ID                string     `json:"_id"`
	DeviceID          string     `json:"device_id"`
	Hostname          string     `json:"hostname"`
	IPAddress         string     `json:"ip_address"`
	MACAddress        string     `json:"mac_address"`
	OS                string     `json:"os"`
	Subnet            string     `json:"subnet"`
	Status            string     `json:"status"` // active, closed
	ConnectedAt       time.Time  `json:"connected_at"`
	LastActiveAt      time.Time  `json:"last_active_at"`
	DisconnectedAt    *time.Time `json:"disconnected_at,omitempty"`
	DurationSeconds   int        `json:"duration_seconds"`
	LogsSent          int        `json:"logs_sent"`
	MetricsSent       int        `json:"metrics_sent"`
	TerminationReason string     `json:"termination_reason,omitempty"`
}

type DeviceEvent struct {
	ID        string    `json:"_id"`
	DeviceID  string    `json:"device_id"`
	Event     string    `json:"event"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details"`
	Actor     string    `json:"actor,omitempty"`
}

type EnrollmentToken struct {
	ID           string    `json:"id"`
	TokenHash    string    `json:"token_hash"`
	TokenPreview string    `json:"token_preview"`
	CreatedBy    string    `json:"created_by"`
	Reusable     bool      `json:"reusable"`
	Used         bool      `json:"used"`
	UseCount     int       `json:"use_count"`
	DeviceIDs    []string  `json:"device_ids"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Ingestion payload DTOs
type HeartbeatRequest struct {
	DeviceID  string `json:"device_id"`
	Timestamp string `json:"timestamp"`
	Status    string `json:"status"`
}

type MetricItem struct {
	Timestamp      interface{} `json:"timestamp"`
	CPUPercent     float64     `json:"cpu_percent"`
	MemoryPercent  float64     `json:"memory_percent"`
	DiskPercent    float64     `json:"disk_percent"`
	NetworkRXBytes int64       `json:"network_rx_bytes"`
	NetworkTXBytes int64       `json:"network_tx_bytes"`
}

type MetricsBatchRequest struct {
	DeviceID string       `json:"device_id"`
	Metrics  []MetricItem `json:"metrics"`
}

type LogItem struct {
	Timestamp  interface{} `json:"timestamp"`
	OS         string      `json:"os"`
	SourceType string      `json:"source_type"`
	Source     string      `json:"source"`
	EventID    string      `json:"event_id"`
	EventType  string      `json:"event_type"`
	Severity   string      `json:"severity"`
	Message    string      `json:"message"`
	RawLog     interface{} `json:"raw_log"`
	Username   string      `json:"username,omitempty"`
}

type LogsBatchRequest struct {
	DeviceID string    `json:"device_id"`
	Logs     []LogItem `json:"logs"`
}

type ProcessesRequest struct {
	DeviceID  string    `json:"device_id"`
	Processes []Process `json:"processes"`
}

type DeviceRegistrationRequest struct {
	Token        string `json:"token"`
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ip_address"`
	MACAddress   string `json:"mac_address"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	AgentVersion string `json:"agent_version"`
}

type DeviceRegistrationResponse struct {
	DeviceID         string `json:"device_id"`
	DeviceCredential string `json:"device_credential"`
}
