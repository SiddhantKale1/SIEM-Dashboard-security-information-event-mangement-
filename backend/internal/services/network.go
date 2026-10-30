package services

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sentinel/siem-backend/internal/database"
	"github.com/sentinel/siem-backend/internal/models"
)

type NetworkInfo struct {
	ServerIP   string `json:"server_ip"`
	Subnet     string `json:"subnet"`
	Gateway    string `json:"gateway"`
	Interface  string `json:"interface"`
	DetectedAt string `json:"detected_at"`
}

type DiscoveredNode struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	Hostname   string `json:"hostname"`
	Subnet     string `json:"subnet"`
	Status     string `json:"status"`
}

type NetworkManager struct {
	store *database.Store
}

func NewNetworkManager(store *database.Store) *NetworkManager {
	return &NetworkManager{store: store}
}

func (nm *NetworkManager) GetLocalNetworkInfo() NetworkInfo {
	localIP := "127.0.0.1"

	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 500*time.Millisecond)
	if err == nil {
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		localIP = localAddr.IP.String()
		_ = conn.Close()
	} else {
		// Fallback to iterating interfaces
		ifaces, err := net.Interfaces()
		if err == nil {
			for _, iface := range ifaces {
				if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
					continue
				}
				addrs, err := iface.Addrs()
				if err != nil {
					continue
				}
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
						if ipNet.IP.To4() != nil {
							localIP = ipNet.IP.String()
							break
						}
					}
				}
			}
		}
	}

	subnet := "192.168.1.0/24"
	gateway := "192.168.1.1"

	parts := strings.Split(localIP, ".")
	if len(parts) == 4 && parts[0] != "127" {
		subnet = fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		gateway = fmt.Sprintf("%s.%s.%s.1", parts[0], parts[1], parts[2])
	} else if parts[0] == "127" {
		subnet = "127.0.0.0/8"
		gateway = "127.0.0.1"
	}

	ifaceName := "eth0"
	if runtime.GOOS == "windows" {
		ifaceName = "Ethernet/Wi-Fi"
	}

	return NetworkInfo{
		ServerIP:   localIP,
		Subnet:     subnet,
		Gateway:    gateway,
		Interface:  ifaceName,
		DetectedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func (nm *NetworkManager) IsIPInSubnet(ipStr, subnetCIDR string) bool {
	if ipStr == "127.0.0.1" || ipStr == "localhost" {
		return true
	}
	_, ipNet, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ipNet.Contains(ip)
}

func (nm *NetworkManager) ActiveScanSubnet() {
	info := nm.GetLocalNetworkInfo()
	parts := strings.Split(info.ServerIP, ".")
	if len(parts) != 4 || parts[0] == "127" {
		return
	}
	baseIP := fmt.Sprintf("%s.%s.%s", parts[0], parts[1], parts[2])

	var wg sync.WaitGroup
	sem := make(chan struct{}, 50) // limit concurrent pings

	for i := 1; i <= 254; i++ {
		targetIP := fmt.Sprintf("%s.%d", baseIP, i)
		if targetIP == info.ServerIP {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.Command("ping", "-n", "1", "-w", "200", ip)
			} else {
				cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
			}
			_ = cmd.Run()
		}(targetIP)
	}

	wg.Wait()
}

var (
	arpLinuxRegex = regexp.MustCompile(`\(([0-9.]+)\)\s+at\s+([0-9a-fA-F:]{17})`)
	arpWinRegex   = regexp.MustCompile(`([0-9.]+)\s+([0-9a-fA-F-]{17})`)
)

func (nm *NetworkManager) GetARPDevices(activeScan bool) []DiscoveredNode {
	if activeScan {
		nm.ActiveScanSubnet()
	}

	info := nm.GetLocalNetworkInfo()
	devices := make([]DiscoveredNode, 0)

	cmd := exec.Command("arp", "-a")
	out, err := cmd.Output()
	if err != nil {
		return devices
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var ip, mac string
		if runtime.GOOS == "windows" {
			matches := arpWinRegex.FindStringSubmatch(line)
			if len(matches) >= 3 {
				ip = matches[1]
				mac = strings.ToLower(strings.ReplaceAll(matches[2], "-", ":"))
			}
		} else {
			matches := arpLinuxRegex.FindStringSubmatch(line)
			if len(matches) >= 3 {
				ip = matches[1]
				mac = strings.ToLower(matches[2])
			}
		}

		if ip != "" && mac != "" && mac != "ff:ff:ff:ff:ff:ff" {
			if nm.IsIPInSubnet(ip, info.Subnet) {
				devices = append(devices, DiscoveredNode{
					IPAddress:  ip,
					MACAddress: mac,
					Hostname:   fmt.Sprintf("Host-%s", ip[strings.LastIndex(ip, ".")+1:]),
					Subnet:     info.Subnet,
					Status:     "discovered",
				})
			}
		}
	}

	return devices
}

func (nm *NetworkManager) RecordConnectionEvent(deviceID, hostname, ip, mac, osName, eventType string) {
	now := time.Now().UTC()
	info := nm.GetLocalNetworkInfo()

	histories := nm.store.GetConnectionHistory()
	var activeSession *models.ConnectionHistory
	for i := range histories {
		if histories[i].DeviceID == deviceID && histories[i].Status == "active" {
			activeSession = &histories[i]
			break
		}
	}

	if activeSession != nil {
		// If subnet or IP changed, close previous session and create new
		if activeSession.Subnet != info.Subnet || activeSession.IPAddress != ip {
			duration := int(now.Sub(activeSession.ConnectedAt).Seconds())
			activeSession.Status = "closed"
			activeSession.DisconnectedAt = &now
			activeSession.DurationSeconds = duration
			activeSession.TerminationReason = "network_switch"
			activeSession = nil
		}
	}

	if activeSession == nil && eventType == "connected" {
		newSession := models.ConnectionHistory{
			ID:                uuid.New().String(),
			DeviceID:          deviceID,
			Hostname:          hostname,
			IPAddress:         ip,
			MACAddress:        mac,
			OS:                osName,
			Subnet:            info.Subnet,
			Status:            "active",
			ConnectedAt:       now,
			LastActiveAt:      now,
			DurationSeconds:   0,
			LogsSent:          0,
			MetricsSent:       0,
			TerminationReason: "",
		}
		nm.store.AddConnectionHistory(newSession)
	} else if activeSession != nil {
		activeSession.LastActiveAt = now
	}
}
