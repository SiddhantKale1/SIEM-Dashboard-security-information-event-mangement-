package services

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sentinel/siem-backend/internal/models"
)

var (
	userRegex    = regexp.MustCompile(`(?i)(?:for user|for invalid user|user=)\s*([a-zA-Z0-9_\-]+)`)
	processRegex = regexp.MustCompile(`(?i)\(([a-zA-Z0-9_\-]+)\s+pid:`)
)

func HumanizeLog(l *models.Log) {
	msg := strings.TrimSpace(l.Message)
	raw := strings.ToLower(l.RawLog)
	src := strings.ToLower(l.Source)
	eid := strings.ToLower(l.EventID)
	combined := fmt.Sprintf("%s %s %s %s", strings.ToLower(msg), raw, src, eid)

	summary := msg
	if summary == "" {
		summary = "System background activity recorded."
	}
	category := "System Health"

	// 1. Authentication & Logins
	if strings.Contains(combined, "failed password") ||
		strings.Contains(combined, "authentication failure") ||
		strings.Contains(combined, "failed logon") ||
		strings.Contains(combined, "invalid user") ||
		eid == "4625" {

		targetUser := "account"
		matches := userRegex.FindStringSubmatch(combined)
		if len(matches) > 1 {
			targetUser = matches[1]
		}
		category = "Failed Login"
		summary = fmt.Sprintf("Failed authentication: Incorrect credentials supplied for account '%s'.", targetUser)

	} else if strings.Contains(combined, "accepted password") ||
		strings.Contains(combined, "successful logon") ||
		strings.Contains(combined, "session opened") ||
		eid == "4624" {

		targetUser := "user"
		matches := userRegex.FindStringSubmatch(combined)
		if len(matches) > 1 {
			targetUser = matches[1]
		}
		category = "Login Success"
		summary = fmt.Sprintf("Session initiated: User '%s' logged in.", targetUser)

	// 2. Privilege Escalation & Admin Commands
	} else if strings.Contains(combined, "chmod 777") ||
		strings.Contains(combined, "/etc/shadow") ||
		strings.Contains(combined, "/etc/sudoers") ||
		strings.Contains(combined, "sudo") {

		category = "Admin Privilege"
		summary = "Administrative privilege invocation (root/sudo) detected on endpoint."

	// 3. Network Sockets & Port Activity
	} else if src == "kernel_socket" || src == "netstat" || src == "browser_network" ||
		strings.Contains(eid, "conn_") || strings.Contains(combined, "tcp") {

		procName := "process"
		matches := processRegex.FindStringSubmatch(msg)
		if len(matches) > 1 {
			procName = matches[1]
		}
		category = "Network Traffic"
		summary = fmt.Sprintf("Active network communication socket maintained by %s.", procName)

	// 4. Windows System Events
	} else if strings.ToLower(l.OS) == "windows" && strings.Contains(src, "system") {
		category = "Windows OS"
		summary = fmt.Sprintf("Windows system event logged (%s).", l.Source)
	}

	l.FriendlySummary = summary
	l.Category = category
	l.IsPolicyViolation = false
}
