package services

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel/siem-backend/internal/database"
	"github.com/sentinel/siem-backend/internal/models"
)

type MitreTacticInfo struct {
	Name        string
	Tactic      string
	Description string
	URL         string
}

var MitreTactics = map[string]MitreTacticInfo{
	"T1110": {
		Name:        "Brute Force",
		Tactic:      "Credential Access",
		Description: "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.",
		URL:         "https://attack.mitre.org/techniques/T1110/",
	},
	"T1059": {
		Name:        "Command and Scripting Interpreter",
		Tactic:      "Execution",
		Description: "Adversaries may abuse command and script interpreters (e.g. bash, powershell) to execute commands.",
		URL:         "https://attack.mitre.org/techniques/T1059/",
	},
	"T1548": {
		Name:        "Abuse Elevation Control Mechanism",
		Tactic:      "Privilege Escalation",
		Description: "Adversaries may circumvent mechanisms designed to control elevation of privileges to gain higher-level permissions.",
		URL:         "https://attack.mitre.org/techniques/T1548/",
	},
	"T1046": {
		Name:        "Network Service Discovery",
		Tactic:      "Discovery",
		Description: "Adversaries may attempt to get a listing of services running on remote hosts (e.g. nmap, port scans).",
		URL:         "https://attack.mitre.org/techniques/T1046/",
	},
	"T1496": {
		Name:        "Resource Hijacking (Cryptomining)",
		Tactic:      "Impact",
		Description: "Adversaries may leverage computer resources for unauthorized purposes such as cryptocurrency mining.",
		URL:         "https://attack.mitre.org/techniques/T1496/",
	},
	"T1562": {
		Name:        "Impair Defenses",
		Tactic:      "Defense Evasion",
		Description: "Adversaries may disable security tools, firewalls, or logging systems to avoid detection.",
		URL:         "https://attack.mitre.org/techniques/T1562/",
	},
	"T1048": {
		Name:        "Exfiltration Over Alternative Protocol",
		Tactic:      "Exfiltration",
		Description: "Adversaries may steal data by exfiltrating it over unusual network streams or burst channels.",
		URL:         "https://attack.mitre.org/techniques/T1048/",
	},
}

type MetricBaseline struct {
	CPUHistory []float64
	TXHistory  []int64
	LastTX     int64
}

type AIEngine struct {
	mu              sync.Mutex
	failedLogins    map[string][]time.Time
	metricBaselines map[string]*MetricBaseline
	store           *database.Store
	ipRegex         *regexp.Regexp
}

func NewAIEngine(store *database.Store) *AIEngine {
	return &AIEngine{
		failedLogins:    make(map[string][]time.Time),
		metricBaselines: make(map[string]*MetricBaseline),
		store:           store,
		ipRegex:         regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`),
	}
}

func (ae *AIEngine) BuildAnomaly(
	deviceID, hostname, title, severity string,
	confidence int,
	mitreID, summary, rootCause string,
	evidence []string,
	recommendedAction, ipAddress, osName string,
) *models.Anomaly {
	info, ok := MitreTactics[mitreID]
	if !ok {
		info = MitreTacticInfo{
			Name:        "Unknown",
			Tactic:      "General",
			Description: "",
			URL:         "",
		}
	}

	enrichedEvidence := append([]string{
		fmt.Sprintf("Machine: %s (IP: %s, OS: %s, ID: %s)", hostname, ipAddress, strings.Title(osName), deviceID),
	}, evidence...)

	now := time.Now().UTC()
	return &models.Anomaly{
		ID:                uuid.New().String(),
		DeviceID:          deviceID,
		Hostname:          hostname,
		IPAddress:         ipAddress,
		OS:                osName,
		Title:             fmt.Sprintf("[%s - %s] %s", hostname, ipAddress, title),
		Severity:          severity,
		Status:            "active",
		Confidence:        confidence,
		MITREID:           mitreID,
		MITRETechnique:    info.Name,
		MITRETactic:       info.Tactic,
		MITREURL:          info.URL,
		Summary:           summary,
		RootCause:         rootCause,
		Evidence:          enrichedEvidence,
		RecommendedAction: recommendedAction,
		DetectedAt:        now,
		UpdatedAt:         now,
	}
}

func (ae *AIEngine) AnalyzeLogs(deviceID, hostname, ipAddress, osName string, logs []models.Log) []*models.Anomaly {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	anomalies := make([]*models.Anomaly, 0)
	now := time.Now().UTC()

	for _, log := range logs {
		msg := strings.ToLower(log.Message)
		src := strings.ToLower(log.Source)
		raw := strings.ToLower(log.RawLog)
		eid := strings.ToLower(log.EventID)
		combined := fmt.Sprintf("%s %s %s %s", msg, src, raw, eid)

		// 1. SSH / Auth Brute Force Detection (MITRE T1110)
		isAuthFailure := strings.Contains(combined, "failed password") ||
			strings.Contains(combined, "authentication failure") ||
			strings.Contains(combined, "failed logon") ||
			strings.Contains(combined, "invalid user") ||
			((eid == "4625" || src == "sshd") && strings.Contains(combined, "fail"))

		if isAuthFailure {
			hostKey := fmt.Sprintf("%s:auth_fail", deviceID)
			ae.failedLogins[hostKey] = append(ae.failedLogins[hostKey], now)

			// Prune older than 90 seconds
			cutoff := now.Add(-90 * time.Second)
			validTimes := make([]time.Time, 0)
			for _, t := range ae.failedLogins[hostKey] {
				if t.After(cutoff) {
					validTimes = append(validTimes, t)
				}
			}
			ae.failedLogins[hostKey] = validTimes

			failureCount := len(validTimes)
			if failureCount >= 3 {
				attackerIP := "External / Network"
				match := ae.ipRegex.FindString(combined)
				if match != "" {
					attackerIP = match
				}

				sev := "high"
				if failureCount >= 6 {
					sev = "critical"
				}

				sampleMsg := log.Message
				if len(sampleMsg) > 140 {
					sampleMsg = sampleMsg[:140]
				}

				anomaly := ae.BuildAnomaly(
					deviceID,
					hostname,
					fmt.Sprintf("Authentication Brute-Force Wave Detected (%d failures in 90s)", failureCount),
					sev,
					96,
					"T1110",
					fmt.Sprintf("Automated credential brute-force surge detected on %s (%s). Multiple consecutive failed logon attempts originated from %s.", hostname, ipAddress, attackerIP),
					"High-frequency failed logon burst detected in auth logs. Pattern matches dictionary attack or automated SSH/RDP credential spraying.",
					[]string{
						fmt.Sprintf("Detected %d failed login events within sliding 90s window", failureCount),
						fmt.Sprintf("Sample log: %s", sampleMsg),
						fmt.Sprintf("Target Service: %s", log.Source),
						fmt.Sprintf("Source IP: %s", attackerIP),
					},
					fmt.Sprintf("1. Consider isolating endpoint %s (%s) via 1-click quarantine. 2. Block offending IP %s at edge firewall. 3. Audit targeted account credentials.", hostname, ipAddress, attackerIP),
					ipAddress,
					osName,
				)
				anomalies = append(anomalies, anomaly)
				ae.failedLogins[hostKey] = []time.Time{}
			}
		}

		// 2. Privilege Escalation & Sensitive File Tampering (MITRE T1548)
		isPrivEsc := (strings.Contains(combined, "sudo") && (strings.Contains(combined, "chmod 777") || strings.Contains(combined, "/etc/shadow") || strings.Contains(combined, "/etc/sudoers"))) ||
			(strings.Contains(combined, "useradd") && strings.Contains(combined, "root")) ||
			strings.Contains(combined, "passwd root") ||
			(strings.Contains(combined, "pkexec") && strings.Contains(combined, "pwn")) ||
			strings.Contains(combined, "su: auth failure")

		if isPrivEsc {
			sampleMsg := log.Message
			if len(sampleMsg) > 160 {
				sampleMsg = sampleMsg[:160]
			}
			anomaly := ae.BuildAnomaly(
				deviceID,
				hostname,
				"Suspicious Privilege Escalation / Sensitive File Access",
				"critical",
				94,
				"T1548",
				fmt.Sprintf("A command attempted to escalate privileges or modify protected system security files on %s (%s).", hostname, ipAddress),
				"User or spawned subshell attempted modification of critical authentication tables (/etc/shadow or sudoers permissions).",
				[]string{
					fmt.Sprintf("Triggering command/log: %s", sampleMsg),
					fmt.Sprintf("Source subsystem: %s", log.Source),
					fmt.Sprintf("Execution timestamp: %s", now.Format(time.RFC3339)),
				},
				fmt.Sprintf("1. Isolate device %s immediately. 2. Terminate the active TTY session. 3. Review /etc/passwd and sudoers integrity.", hostname),
				ipAddress,
				osName,
			)
			anomalies = append(anomalies, anomaly)
		}

		// 3. Reverse Shell & Suspicious Script Execution (MITRE T1059)
		isReverseShell := strings.Contains(combined, "/dev/tcp/") ||
			strings.Contains(combined, "nc -e") ||
			strings.Contains(combined, "ncat -e") ||
			(strings.Contains(combined, "mkfifo") && strings.Contains(combined, "sh")) ||
			(strings.Contains(combined, "curl") && strings.Contains(combined, "| bash")) ||
			(strings.Contains(combined, "wget") && strings.Contains(combined, "| sh")) ||
			strings.Contains(combined, "powershell -enc") ||
			strings.Contains(combined, "powershell.exe -w hidden")

		if isReverseShell {
			sampleMsg := log.Message
			if len(sampleMsg) > 160 {
				sampleMsg = sampleMsg[:160]
			}
			anomaly := ae.BuildAnomaly(
				deviceID,
				hostname,
				"Interactive Reverse Shell / Piped Execution Payload",
				"critical",
				98,
				"T1059",
				fmt.Sprintf("Suspicious interactive reverse-shell or pipe-to-shell payload execution detected on host %s (%s).", hostname, ipAddress),
				"Process spawned an unencrypted interactive socket or downloaded remote code directly into an interpreter shell.",
				[]string{
					fmt.Sprintf("Signature match: %s", sampleMsg),
					fmt.Sprintf("Execution Environment: %s", osName),
					fmt.Sprintf("Subsystem: %s", log.Source),
				},
				fmt.Sprintf("1. Isolate host %s immediately from network. 2. Kill spawned parent PID and socket connection. 3. Inspect temporary directories.", hostname),
				ipAddress,
				osName,
			)
			anomalies = append(anomalies, anomaly)
		}

		// 4. Impair Defenses / Firewall Tampering (MITRE T1562)
		isDefenseImpairment := strings.Contains(combined, "ufw disable") ||
			strings.Contains(combined, "iptables -f") ||
			strings.Contains(combined, "setenforce 0") ||
			(strings.Contains(combined, "netsh advfirewall set") && strings.Contains(combined, "off")) ||
			strings.Contains(combined, "stop-service windefend") ||
			strings.Contains(combined, "systemctl stop auditd")

		if isDefenseImpairment {
			sampleMsg := log.Message
			if len(sampleMsg) > 140 {
				sampleMsg = sampleMsg[:140]
			}
			anomaly := ae.BuildAnomaly(
				deviceID,
				hostname,
				"Host Defense Impairment / Firewall Disabled",
				"high",
				95,
				"T1562",
				fmt.Sprintf("Host security defenses or local packet filter disabled on %s (%s).", hostname, ipAddress),
				"Local administration command or unauthorized script deliberately stopped host firewall or audit daemon.",
				[]string{
					fmt.Sprintf("Action: %s", sampleMsg),
					fmt.Sprintf("Target Service: %s", log.Source),
				},
				fmt.Sprintf("1. Re-enable firewall on %s immediately. 2. Verify identity of administrator user executing the command.", hostname),
				ipAddress,
				osName,
			)
			anomalies = append(anomalies, anomaly)
		}
	}

	for _, a := range anomalies {
		ae.store.AddAnomaly(a)
	}

	return anomalies
}

func (ae *AIEngine) AnalyzeMetrics(deviceID, hostname, ipAddress, osName string, metrics []models.Metric) []*models.Anomaly {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	anomalies := make([]*models.Anomaly, 0)
	baseline, ok := ae.metricBaselines[deviceID]
	if !ok {
		baseline = &MetricBaseline{
			CPUHistory: make([]float64, 0),
			TXHistory:  make([]int64, 0),
			LastTX:     0,
		}
		ae.metricBaselines[deviceID] = baseline
	}

	for _, m := range metrics {
		cpu := m.CPUPercent
		mem := m.MemoryPercent
		tx := m.NetworkTXBytes

		baseline.CPUHistory = append(baseline.CPUHistory, cpu)
		if len(baseline.CPUHistory) > 20 {
			baseline.CPUHistory = baseline.CPUHistory[1:]
		}

		// 1. Sustained High-CPU Cryptominer Anomaly (MITRE T1496)
		var totalCPU float64
		for _, c := range baseline.CPUHistory {
			totalCPU += c
		}
		avgCPU := totalCPU / float64(len(baseline.CPUHistory))

		highCount := 0
		recentStart := len(baseline.CPUHistory) - 5
		if recentStart < 0 {
			recentStart = 0
		}
		for _, c := range baseline.CPUHistory[recentStart:] {
			if c > 85.0 {
				highCount++
			}
		}

		if cpu > 88.0 && (avgCPU > 70.0 || highCount >= 3) {
			anomaly := ae.BuildAnomaly(
				deviceID,
				hostname,
				"Abnormal Sustained CPU Spike (Cryptomining Signature)",
				"high",
				89,
				"T1496",
				fmt.Sprintf("Host %s (%s) is running at sustained high CPU (%.1f%%), indicating possible cryptojacking or rogue computation.", hostname, ipAddress, cpu),
				fmt.Sprintf("Host metric telemetry exceeded baseline threshold. Average CPU sustained at %.1f%% across recent reporting cycles.", avgCPU),
				[]string{
					fmt.Sprintf("Instantaneous CPU: %.1f%%", cpu),
					fmt.Sprintf("20-sample Rolling Baseline: %.1f%%", avgCPU),
					fmt.Sprintf("Memory Utilization: %.1f%%", mem),
				},
				"1. Inspect running processes on endpoint for unknown binaries (e.g. xmrig, minerd). 2. Restrict outbound mining pool ports (3333, 4444, 5555).",
				ipAddress,
				osName,
			)
			anomalies = append(anomalies, anomaly)
		}

		// 2. Exfiltration / Network Outbound Surge (MITRE T1048)
		prevTX := baseline.LastTX
		if prevTX == 0 {
			prevTX = tx
		}
		txDelta := tx - prevTX
		if txDelta < 0 {
			txDelta = 0
		}
		baseline.LastTX = tx
		baseline.TXHistory = append(baseline.TXHistory, txDelta)
		if len(baseline.TXHistory) > 20 {
			baseline.TXHistory = baseline.TXHistory[1:]
		}

		var sumTX int64
		for _, d := range baseline.TXHistory {
			sumTX += d
		}
		var avgTX int64
		if len(baseline.TXHistory) > 0 {
			avgTX = sumTX / int64(len(baseline.TXHistory))
		}

		if txDelta > 50*1024*1024 || (avgTX > 0 && txDelta > 10*avgTX && txDelta > 15*1024*1024) {
			mbTransferred := float64(txDelta) / (1024 * 1024)
			avgMB := float64(avgTX) / (1024 * 1024)
			var burstFactor float64
			if avgTX > 0 {
				burstFactor = float64(txDelta) / float64(avgTX)
			} else {
				burstFactor = 1.0
			}

			anomaly := ae.BuildAnomaly(
				deviceID,
				hostname,
				fmt.Sprintf("Massive Outbound Network Traffic Burst (%.1f MB)", mbTransferred),
				"high",
				87,
				"T1048",
				fmt.Sprintf("Unusual burst of outbound network traffic detected from %s (%s). Potential active data exfiltration.", hostname, ipAddress),
				fmt.Sprintf("Outbound transmission delta of %.1f MB significantly exceeds normal host telemetry baseline.", mbTransferred),
				[]string{
					fmt.Sprintf("Current TX Delta: %.2f MB", mbTransferred),
					fmt.Sprintf("Historical Average Delta: %.2f MB", avgMB),
					fmt.Sprintf("Burst Factor: %.1fx baseline", burstFactor),
				},
				"1. Inspect active network sockets via netstat/ss on host. 2. Identify destination IP and port. 3. Isolate host if destination is untrusted.",
				ipAddress,
				osName,
			)
			anomalies = append(anomalies, anomaly)
		}
	}

	for _, a := range anomalies {
		ae.store.AddAnomaly(a)
	}

	return anomalies
}

type SuspiciousProcDef struct {
	MitreCode string
	Severity  string
	Desc      string
}

var SuspiciousProcessNames = map[string]SuspiciousProcDef{
	"xmrig":    {"T1496", "high", "Cryptocurrency miner daemon"},
	"minerd":   {"T1496", "high", "Cryptocurrency miner daemon"},
	"nmap":     {"T1046", "medium", "Network port scanning tool"},
	"masscan":  {"T1046", "medium", "High-speed network scanner"},
	"mimikatz": {"T1110", "critical", "Credential dumping utility"},
	"hydra":    {"T1110", "high", "Network logon cracking tool"},
	"john":     {"T1110", "medium", "Password hash cracking tool"},
	"hashcat":  {"T1110", "medium", "Password cracking tool"},
	"chisel":   {"T1059", "high", "TCP/UDP tunnel over HTTP"},
	"ngrok":    {"T1059", "medium", "Reverse proxy / tunnel"},
}

func (ae *AIEngine) AnalyzeProcesses(deviceID, hostname, ipAddress, osName string, processes []models.Process) []*models.Anomaly {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	anomalies := make([]*models.Anomaly, 0)

	for _, proc := range processes {
		pname := strings.ToLower(proc.Name)
		pexec := strings.ToLower(proc.Executable)

		for target, def := range SuspiciousProcessNames {
			if strings.Contains(pname, target) || strings.Contains(pexec, target) {
				anomaly := ae.BuildAnomaly(
					deviceID,
					hostname,
					fmt.Sprintf("Malicious / Dual-Use Tool Process Detected (%s)", target),
					def.Severity,
					95,
					def.MitreCode,
					fmt.Sprintf("Endpoint %s (%s) spawned a suspicious process: '%s' (%s).", hostname, ipAddress, proc.Name, def.Desc),
					fmt.Sprintf("Binary execution matches signature for %s.", def.Desc),
					[]string{
						fmt.Sprintf("Process Name: %s", proc.Name),
						fmt.Sprintf("PID: %d", proc.PID),
						fmt.Sprintf("Executable Path: %s", proc.Executable),
						fmt.Sprintf("CPU Percent: %.1f%%", proc.CPUPercent),
					},
					fmt.Sprintf("1. Terminate PID %d. 2. Locate and quarantine executable file. 3. Investigate parent process lineage.", proc.PID),
					ipAddress,
					osName,
				)
				anomalies = append(anomalies, anomaly)
			}
		}
	}

	for _, a := range anomalies {
		ae.store.AddAnomaly(a)
	}

	return anomalies
}

func (ae *AIEngine) CalculatePosture(anomalies []*models.Anomaly) (int, string, map[string]int) {
	critical := 0
	high := 0
	medium := 0
	active := 0
	tacticCounts := make(map[string]int)

	for _, a := range anomalies {
		if a.Status == "active" {
			active++
			switch a.Severity {
			case "critical":
				critical++
			case "high":
				high++
			case "medium":
				medium++
			}
			tactic := a.MITRETactic
			if tactic == "" {
				tactic = "General"
			}
			tacticCounts[tactic]++
		}
	}

	calculatedRisk := (critical * 35) + (high * 15) + (medium * 5)
	if calculatedRisk > 100 {
		calculatedRisk = 100
	}

	var posture string
	if active == 0 {
		posture = "SECURE"
	} else if calculatedRisk > 70 {
		posture = "CRITICAL"
	} else if calculatedRisk > 35 {
		posture = "ELEVATED"
	} else {
		posture = "MONITORED"
	}

	return calculatedRisk, posture, tacticCounts
}
