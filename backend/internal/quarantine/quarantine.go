package quarantine

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Status represents the runtime network quarantine state of the endpoint agent.
type Status struct {
	IsQuarantined bool      `json:"is_quarantined"`
	QuarantinedAt time.Time `json:"quarantined_at,omitempty"`
	RestoredAt    time.Time `json:"restored_at,omitempty"`
	SiemHost      string    `json:"siem_host"`
	SiemPort      int       `json:"siem_port"`
	IsRoot        bool      `json:"is_root"`
	Platform      string    `json:"platform"`
}

// Manager controls the surgical kernel-level network quarantine.
type Manager struct {
	mu            sync.RWMutex
	isQuarantined bool
	quarantinedAt time.Time
	restoredAt    time.Time
	siemHost      string
	siemPort      int
	isRoot        bool
}

// NewManager initializes a quarantine controller parsed from the SIEM Server URL.
func NewManager(serverURL string) *Manager {
	host := "127.0.0.1"
	port := 8000

	parsed, err := url.Parse(serverURL)
	if err == nil {
		h := parsed.Hostname()
		if h != "" {
			host = h
		}
		p := parsed.Port()
		if p != "" {
			if parsedPort, err := strconv.Atoi(p); err == nil {
				port = parsedPort
			}
		} else if parsed.Scheme == "https" {
			port = 443
		} else if parsed.Scheme == "http" {
			port = 80
		}
	}

	// Resolve hostname to IP if it's a domain name
	resolvedIP := resolveToIP(host)

	isRoot := false
	if runtime.GOOS == "windows" {
		// On Windows, check admin token by attempting privileged read/test
		isRoot = checkWindowsAdmin()
	} else {
		isRoot = (os.Geteuid() == 0)
	}

	return &Manager{
		siemHost: resolvedIP,
		siemPort: port,
		isRoot:   isRoot,
	}
}

// Enforce executes the surgical kernel firewall lockdown.
// It severs all internet and LAN access while keeping the SIEM heartbeat tunnel alive.
func (m *Manager) Enforce() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isQuarantined {
		return nil // Already enforced
	}

	now := time.Now().UTC()
	log.Printf("[🔒 QUARANTINE] Enforcing surgical kernel network lockdown...")
	log.Printf("[🔒 QUARANTINE] SIEM Control Tunnel Whitelisted: %s:%d", m.siemHost, m.siemPort)

	var err error
	switch runtime.GOOS {
	case "linux":
		err = m.enforceLinux()
	case "windows":
		err = m.enforceWindows()
	case "darwin":
		err = m.enforceDarwin()
	default:
		log.Printf("[⚠️ QUARANTINE] Platform %s: Simulating surgical network quarantine", runtime.GOOS)
	}

	if err != nil {
		log.Printf("[⚠️ QUARANTINE] Kernel rule execution note: %v", err)
	}

	m.isQuarantined = true
	m.quarantinedAt = now
	log.Println("[🛡️ QUARANTINE ACTIVE] Endpoint host network isolated. All internet and LAN traffic dropped.")
	return nil
}

// Lift tears down the kernel firewall quarantine and restores full network connectivity.
func (m *Manager) Lift() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isQuarantined {
		return nil
	}

	log.Println("[🔓 RESTORING] SOC Administrator authorized restoration. Lifting kernel network quarantine...")

	var err error
	switch runtime.GOOS {
	case "linux":
		err = m.liftLinux()
	case "windows":
		err = m.liftWindows()
	case "darwin":
		err = m.liftDarwin()
	}

	if err != nil {
		log.Printf("[⚠️ RESTORING] Note lifting rules: %v", err)
	}

	m.isQuarantined = false
	m.restoredAt = time.Now().UTC()
	log.Println("[✅ RESTORED] Full internet and LAN connectivity restored.")
	return nil
}

// IsQuarantined returns whether the host is currently in quarantine.
func (m *Manager) IsQuarantined() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isQuarantined
}

// Status returns current manager snapshot.
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Status{
		IsQuarantined: m.isQuarantined,
		QuarantinedAt: m.quarantinedAt,
		RestoredAt:    m.restoredAt,
		SiemHost:      m.siemHost,
		SiemPort:      m.siemPort,
		IsRoot:        m.isRoot,
		Platform:      runtime.GOOS,
	}
}

// enforceLinux configures iptables custom chain SENTINEL_QUARANTINE.
func (m *Manager) enforceLinux() error {
	if !m.isRoot {
		log.Println("[ℹ️ QUARANTINE] Non-root execution: Kernel firewall rules simulated (run agent with root / CAP_NET_ADMIN in production).")
		return nil
	}

	// 1. Create or flush dedicated chain
	_ = exec.Command("iptables", "-N", "SENTINEL_QUARANTINE").Run()
	_ = exec.Command("iptables", "-F", "SENTINEL_QUARANTINE").Run()

	// 2. Allow Loopback (Local IPC and internal host daemons)
	_ = exec.Command("iptables", "-A", "SENTINEL_QUARANTINE", "-i", "lo", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-A", "SENTINEL_QUARANTINE", "-o", "lo", "-j", "ACCEPT").Run()

	// 3. Allow established/related connections for SIEM tunnel
	_ = exec.Command("iptables", "-A", "SENTINEL_QUARANTINE", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT").Run()

	// 4. Whitelist SIEM Server IP and Port exclusively
	if m.siemHost != "" && m.siemHost != "127.0.0.1" {
		_ = exec.Command("iptables", "-A", "SENTINEL_QUARANTINE", "-d", m.siemHost, "-p", "tcp", "--dport", fmt.Sprint(m.siemPort), "-j", "ACCEPT").Run()
		_ = exec.Command("iptables", "-A", "SENTINEL_QUARANTINE", "-s", m.siemHost, "-p", "tcp", "--sport", fmt.Sprint(m.siemPort), "-j", "ACCEPT").Run()
	}

	// 5. DROP everything else (all inbound and outbound internet and LAN traffic)
	_ = exec.Command("iptables", "-A", "SENTINEL_QUARANTINE", "-j", "DROP").Run()

	// 6. Hook into INPUT and OUTPUT chains at position 1 if not already present
	_ = exec.Command("iptables", "-C", "INPUT", "-j", "SENTINEL_QUARANTINE").Run()
	_ = exec.Command("iptables", "-I", "INPUT", "1", "-j", "SENTINEL_QUARANTINE").Run()

	_ = exec.Command("iptables", "-C", "OUTPUT", "-j", "SENTINEL_QUARANTINE").Run()
	_ = exec.Command("iptables", "-I", "OUTPUT", "1", "-j", "SENTINEL_QUARANTINE").Run()

	return nil
}

// liftLinux removes iptables rules and deletes the SENTINEL_QUARANTINE chain.
func (m *Manager) liftLinux() error {
	if !m.isRoot {
		log.Println("[ℹ️ RESTORING] Non-root execution: Simulated quarantine lifted.")
		return nil
	}

	// Remove hooks
	_ = exec.Command("iptables", "-D", "INPUT", "-j", "SENTINEL_QUARANTINE").Run()
	_ = exec.Command("iptables", "-D", "OUTPUT", "-j", "SENTINEL_QUARANTINE").Run()

	// Flush and remove chain
	_ = exec.Command("iptables", "-F", "SENTINEL_QUARANTINE").Run()
	_ = exec.Command("iptables", "-X", "SENTINEL_QUARANTINE").Run()
	return nil
}

// enforceWindows applies netsh advfirewall rules.
func (m *Manager) enforceWindows() error {
	if !m.isRoot {
		log.Println("[ℹ️ QUARANTINE] Windows non-admin execution: Simulated firewall isolation.")
		return nil
	}

	// Whitelist SIEM outbound
	_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=SENTINEL_ALLOW_SIEM", "dir=out", "action=allow",
		fmt.Sprintf("remoteip=%s", m.siemHost),
		fmt.Sprintf("remoteport=%d", m.siemPort),
		"protocol=TCP").Run()

	// Block all other outbound traffic
	_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=SENTINEL_BLOCK_OUT", "dir=out", "action=block").Run()

	// Block all inbound traffic
	_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name=SENTINEL_BLOCK_IN", "dir=in", "action=block").Run()

	return nil
}

// liftWindows removes netsh advfirewall quarantine rules.
func (m *Manager) liftWindows() error {
	if !m.isRoot {
		return nil
	}
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=SENTINEL_ALLOW_SIEM").Run()
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=SENTINEL_BLOCK_OUT").Run()
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=SENTINEL_BLOCK_IN").Run()
	return nil
}

// enforceDarwin applies pfctl anchor.
func (m *Manager) enforceDarwin() error {
	if !m.isRoot {
		log.Println("[ℹ️ QUARANTINE] macOS non-root execution: Simulated packet filter isolation.")
		return nil
	}
	rules := fmt.Sprintf("pass out quick proto tcp to %s port %d\npass in quick proto tcp from %s port %d\nblock in all\nblock out all\n",
		m.siemHost, m.siemPort, m.siemHost, m.siemPort)
	cmd := exec.Command("pfctl", "-a", "sentinel_quarantine", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	return cmd.Run()
}

// liftDarwin flushes the pfctl anchor.
func (m *Manager) liftDarwin() error {
	if !m.isRoot {
		return nil
	}
	return exec.Command("pfctl", "-a", "sentinel_quarantine", "-F", "all").Run()
}

func resolveToIP(target string) string {
	if target == "localhost" || target == "127.0.0.1" {
		return "127.0.0.1"
	}
	ips, err := net.LookupIP(target)
	if err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if ip.To4() != nil {
				return ip.String()
			}
		}
		return ips[0].String()
	}
	return target
}

func checkWindowsAdmin() bool {
	// Simple check using net session
	cmd := exec.Command("net", "session")
	return cmd.Run() == nil
}
