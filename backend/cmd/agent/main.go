package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	gocpu "github.com/shirou/gopsutil/v3/cpu"
	godisk "github.com/shirou/gopsutil/v3/disk"
	gomem "github.com/shirou/gopsutil/v3/mem"
	gonet "github.com/shirou/gopsutil/v3/net"
	goproc "github.com/shirou/gopsutil/v3/process"

	"github.com/sentinel/siem-backend/internal/models"
	"github.com/sentinel/siem-backend/internal/quarantine"
)

type AgentConfig struct {
	ServerURL        string `json:"server_url"`
	EnrollmentToken  string `json:"enrollment_token,omitempty"`
	DeviceID         string `json:"device_id,omitempty"`
	DeviceCredential string `json:"device_credential,omitempty"`
}

func main() {
	serverFlag := flag.String("server", "http://127.0.0.1:8000", "SIEM Server URL")
	tokenFlag := flag.String("token", "", "Enrollment Token")
	configFlag := flag.String("config", "agent_config.json", "Path to config file")
	flag.Parse()

	log.Println("[*] Starting Native Go SIEM Universal Security Agent...")

	cfg := loadOrEnroll(*serverFlag, *tokenFlag, *configFlag)
	client := &http.Client{Timeout: 10 * time.Second}
	qMgr := quarantine.NewManager(cfg.ServerURL)

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	heartbeatTicker := time.NewTicker(5 * time.Second)
	metricsTicker := time.NewTicker(10 * time.Second)
	defer heartbeatTicker.Stop()
	defer metricsTicker.Stop()

	// Initial heartbeat immediately
	sendHeartbeat(client, cfg, qMgr, "online")

	log.Printf("[+] Go Agent active and monitoring host: %s (Device ID: %s)", cfg.ServerURL, cfg.DeviceID)

	for {
		select {
		case <-heartbeatTicker.C:
			status := "online"
			if qMgr.IsQuarantined() {
				status = "isolated"
			}
			sendHeartbeat(client, cfg, qMgr, status)
		case <-metricsTicker.C:
			if !qMgr.IsQuarantined() {
				sendMetricsAndTelemetry(client, cfg)
			}
		case <-stopChan:
			log.Println("[*] Shutting down agent; notifying server of offline status...")
			if qMgr.IsQuarantined() {
				_ = qMgr.Lift()
			}
			sendHeartbeat(client, cfg, qMgr, "offline")
			return
		}
	}
}

func loadOrEnroll(serverURL, token, configPath string) *AgentConfig {
	cfg := &AgentConfig{
		ServerURL:       serverURL,
		EnrollmentToken: token,
	}

	if data, err := os.ReadFile(configPath); err == nil {
		_ = json.Unmarshal(data, cfg)
	}

	if cfg.DeviceID != "" && cfg.DeviceCredential != "" {
		return cfg
	}

	if cfg.EnrollmentToken == "" {
		log.Fatalf("[-] Error: Enrollment token required. Pass -token <TOKEN>")
	}

	hostname, _ := os.Hostname()
	ipAddress := getOutboundIP()
	macAddress := getMACAddress()

	reqPayload := models.DeviceRegistrationRequest{
		Token:        cfg.EnrollmentToken,
		Hostname:     hostname,
		IPAddress:    ipAddress,
		MACAddress:   macAddress,
		OS:           runtime.GOOS,
		OSVersion:    runtime.Version(),
		AgentVersion: "2.0.0-golang-native",
	}

	bodyBytes, _ := json.Marshal(reqPayload)
	endpoint := fmt.Sprintf("%s/api/v1/enrollment/register", strings.TrimRight(cfg.ServerURL, "/"))
	resp, err := http.Post(endpoint, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		log.Fatalf("[-] Failed to connect to server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		log.Fatalf("[-] Registration failed (HTTP %d): %s", resp.StatusCode, string(respBytes))
	}

	var regResp models.DeviceRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		log.Fatalf("[-] Failed to decode registration response: %v", err)
	}

	cfg.DeviceID = regResp.DeviceID
	cfg.DeviceCredential = regResp.DeviceCredential

	// Persist config
	if dir := filepath.Dir(configPath); dir != "." {
		_ = os.MkdirAll(dir, 0755)
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	_ = os.WriteFile(configPath, data, 0600)

	log.Printf("[+] Registered successfully as device: %s", cfg.DeviceID)
	return cfg
}

func sendHeartbeat(client *http.Client, cfg *AgentConfig, qMgr *quarantine.Manager, status string) {
	endpoint := fmt.Sprintf("%s/api/v1/agent/heartbeat", strings.TrimRight(cfg.ServerURL, "/"))
	payload := models.HeartbeatRequest{
		DeviceID:  cfg.DeviceID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    status,
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cfg.DeviceCredential))

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[!] Heartbeat failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {
		bodyBytes, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(bodyBytes), "Device is isolated") {
			if !qMgr.IsQuarantined() {
				log.Println("[⚠️ QUARANTINE DIRECTIVE] Received device isolation order from Sentinel SOC.")
				_ = qMgr.Enforce()
			}
		}
	} else if resp.StatusCode == http.StatusOK {
		if qMgr.IsQuarantined() {
			log.Println("[🔓 RESTORATION DIRECTIVE] Received access restoration order from Sentinel SOC.")
			_ = qMgr.Lift()
		}
	}
}

func sendMetricsAndTelemetry(client *http.Client, cfg *AgentConfig) {
	serverBase := strings.TrimRight(cfg.ServerURL, "/")

	// 1. Gather real hardware metrics
	cpuPct := 0.0
	if pcts, err := gocpu.Percent(0, false); err == nil && len(pcts) > 0 {
		cpuPct = pcts[0]
	}

	memPct := 0.0
	if vmem, err := gomem.VirtualMemory(); err == nil {
		memPct = vmem.UsedPercent
	}

	diskPct := 0.0
	rootPath := "/"
	if runtime.GOOS == "windows" {
		rootPath = "C:\\"
	}
	if d, err := godisk.Usage(rootPath); err == nil {
		diskPct = d.UsedPercent
	}

	var rxBytes int64
	var txBytes int64
	if ioCounters, err := gonet.IOCounters(false); err == nil && len(ioCounters) > 0 {
		rxBytes = int64(ioCounters[0].BytesRecv)
		txBytes = int64(ioCounters[0].BytesSent)
	}

	metric := models.MetricItem{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		CPUPercent:     cpuPct,
		MemoryPercent:  memPct,
		DiskPercent:    diskPct,
		NetworkRXBytes: rxBytes,
		NetworkTXBytes: txBytes,
	}

	// Post metrics
	metricsPayload := models.MetricsBatchRequest{
		DeviceID: cfg.DeviceID,
		Metrics:  []models.MetricItem{metric},
	}
	postJSON(client, fmt.Sprintf("%s/api/v1/agent/metrics", serverBase), metricsPayload, cfg.DeviceCredential)

	// 2. Gather top 40 processes
	if procs, err := goproc.Processes(); err == nil {
		items := make([]models.Process, 0, 40)
		for _, p := range procs {
			name, err := p.Name()
			if err != nil || name == "" {
				continue
			}
			cPct, _ := p.CPUPercent()
			mPct, _ := p.MemoryPercent()
			uName, _ := p.Username()
			exePath, _ := p.Exe()

			items = append(items, models.Process{
				PID:           int(p.Pid),
				Name:          name,
				CPUPercent:    cPct,
				MemoryPercent: float64(mPct),
				Executable:    exePath,
				Username:      uName,
			})
			if len(items) >= 40 {
				break
			}
		}
		if len(items) > 0 {
			procPayload := models.ProcessesRequest{
				DeviceID:  cfg.DeviceID,
				Processes: items,
			}
			postJSON(client, fmt.Sprintf("%s/api/v1/agent/processes", serverBase), procPayload, cfg.DeviceCredential)
		}
	}
}

func postJSON(client *http.Client, url string, payload interface{}, token string) {
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func getMACAddress() string {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.HardwareAddr != nil && len(iface.HardwareAddr) == 6 {
				return strings.ToLower(iface.HardwareAddr.String())
			}
		}
	}
	return "02:00:00:00:00:01"
}
