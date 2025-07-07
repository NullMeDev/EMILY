//go:build linux
// +build linux

package scanner

import (
	"context"
	"crypto/md5"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/models"
)

// LinuxWiFiScanner implements WiFi scanning for Linux systems
type LinuxWiFiScanner struct {
	config    *config.Config
	running   bool
	iface     string
}

// WiFiScanResult represents a single WiFi scan result
type WiFiScanResult struct {
	BSSID        string
	SSID         string
	Frequency    int
	Channel      int
	SignalLevel  int
	Encryption   string
	Mode         string
	Capabilities []string
	Vendor       string
}

// NewLinuxWiFiScanner creates a new Linux WiFi scanner
func NewLinuxWiFiScanner(cfg *config.Config) (*LinuxWiFiScanner, error) {
	scanner := &LinuxWiFiScanner{
		config: cfg,
	}

	// Auto-detect wireless interface if not specified in config
	if cfg.Detection.WiFi.Interface != "" {
		scanner.iface = cfg.Detection.WiFi.Interface
	} else {
		iface, err := scanner.detectWirelessInterface()
		if err != nil {
			return nil, fmt.Errorf("failed to detect wireless interface: %w", err)
		}
		scanner.iface = iface
	}

	return scanner, nil
}

// detectWirelessInterface finds the first available wireless interface
func (w *LinuxWiFiScanner) detectWirelessInterface() (string, error) {
	// Try to find wireless interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if strings.HasPrefix(iface.Name, "wlan") || 
		   strings.HasPrefix(iface.Name, "wlp") ||
		   strings.HasPrefix(iface.Name, "wifi") {
			return iface.Name, nil
		}
	}

	

	return "", fmt.Errorf("no wireless interface found")
}

// Start starts the WiFi scanner
func (w *LinuxWiFiScanner) Start(ctx context.Context) error {
	w.running = true
	return nil
}

// Stop stops the WiFi scanner
func (w *LinuxWiFiScanner) Stop() error {
	w.running = false
	return nil
}

// Scan performs a WiFi scan and returns detected devices
func (w *LinuxWiFiScanner) Scan(ctx context.Context, duration time.Duration) ([]models.Device, error) {
	if !w.running {
		return nil, fmt.Errorf("scanner not running")
	}

	// Perform the actual WiFi scan
	scanResults, err := w.performScan(ctx)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Convert scan results to device models
	devices := make([]models.Device, 0, len(scanResults))
	now := time.Now()

	for _, result := range scanResults {
		device := models.Device{
			ID:           w.generateDeviceID("wifi", result.BSSID),
			Type:         "wifi",
			MAC:          result.BSSID,
			Name:         result.SSID,
			Manufacturer: w.getVendorFromMAC(result.BSSID),
			SignalLevel:  result.SignalLevel,
			Channel:      result.Channel,
			Frequency:    result.Frequency,
			Encryption:   result.Encryption,
			FirstSeen:    now,
			LastSeen:     now,
			SeenCount:    1,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		// Assess potential threats
		device.ThreatLevel = w.assessWiFiThreat(&device, &result)

		devices = append(devices, device)
	}

	return devices, nil
}

// performScan executes the actual WiFi scan using iwlist
func (w *LinuxWiFiScanner) performScan(ctx context.Context) ([]WiFiScanResult, error) {
return w.performIwScan(ctx)
}

// performIwScan uses the newer 'iw' command as fallback
func (w *LinuxWiFiScanner) performIwScan(ctx context.Context) ([]WiFiScanResult, error) {
	cmd := exec.CommandContext(ctx, "iw", "dev", w.iface, "scan")
	output, err := cmd.Output()
	if err != nil {
	return nil, fmt.Errorf("iw scan command failed: %w", err)
	}

	return w.parseIwOutput(string(output))
}


// parseIwOutput parses the output from iw scan
func (w *LinuxWiFiScanner) parseIwOutput(output string) ([]WiFiScanResult, error) {
	results := make([]WiFiScanResult, 0)
	lines := strings.Split(output, "\n")
	
	var current *WiFiScanResult
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// New BSS (Basic Service Set)
		if strings.HasPrefix(line, "BSS ") {
			if current != nil {
				results = append(results, *current)
			}
			current = &WiFiScanResult{}
			
			// Extract BSSID
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				bssid := strings.TrimSuffix(parts[1], "(on")
				current.BSSID = strings.ToLower(bssid)
			}
		}
		
		if current == nil {
			continue
		}
		
		// SSID
		if strings.Contains(line, "SSID:") {
			ssid := strings.TrimPrefix(line, "SSID: ")
			current.SSID = ssid
		}
		
		// Frequency
		if strings.Contains(line, "freq:") {
			re := regexp.MustCompile(`freq: (\d+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				if freq, err := strconv.Atoi(matches[1]); err == nil {
					current.Frequency = freq
					current.Channel = w.frequencyToChannel(freq)
				}
			}
		}
		
		// Signal strength
		if strings.Contains(line, "signal:") {
			re := regexp.MustCompile(`signal: (-?\d+\.\d+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				if signal, err := strconv.ParseFloat(matches[1], 64); err == nil {
					current.SignalLevel = int(signal)
				}
			}
		}
		
		// Capabilities (includes encryption info)
		if strings.Contains(line, "capability:") {
			if strings.Contains(line, "Privacy") {
				current.Encryption = "WEP"
			}
		}
		
		// WPA/WPA2
		if strings.Contains(line, "WPA:") {
			current.Encryption = "WPA"
		}
		if strings.Contains(line, "RSN:") {
			current.Encryption = "WPA2"
		}
	}
	
	// Add the last result
	if current != nil {
		results = append(results, *current)
	}
	
	return results, nil
}

// frequencyToChannel converts frequency in MHz to WiFi channel number
func (w *LinuxWiFiScanner) frequencyToChannel(freq int) int {
	// 2.4GHz band
	if freq >= 2412 && freq <= 2484 {
		if freq == 2484 {
			return 14
		}
		return (freq-2412)/5 + 1
	}
	
	// 5GHz band
	if freq >= 5170 && freq <= 5825 {
		return (freq - 5000) / 5
	}
	
	return 0
}

// getVendorFromMAC attempts to identify the vendor from MAC address
func (w *LinuxWiFiScanner) getVendorFromMAC(mac string) string {
	if len(mac) < 8 {
		return "Unknown"
	}
	
	// Extract OUI (first 3 octets)
	oui := strings.ReplaceAll(mac[:8], ":", "")
	oui = strings.ToUpper(oui)
	
	// Common OUI mappings (this would typically come from a database)
	ouiMap := map[string]string{
		"001122": "Apple",
		"8863DF": "Apple", 
		"A45E60": "Apple",
		"40B395": "Samsung",
		"E8E5D6": "Samsung",
		"B4F61C": "Samsung",
		"00E04C": "Realtek",
		"001B63": "Intel",
		"7C7A91": "Intel",
		"AC220B": "Broadcom",
		"000F3D": "Broadcom",
		"001CF0": "D-Link",
		"0018E7": "Netgear",
		"2C3033": "Netgear",
		"002722": "Netgear",
		"001E2A": "Cisco",
		"68BC0C": "TP-Link",
		"EC172F": "TP-Link",
		"ACE2D3": "Ubiquiti",
		"E063DA": "Ubiquiti",
	}
	
	if vendor, exists := ouiMap[oui]; exists {
		return vendor
	}
	
	return "Unknown"
}

// generateDeviceID creates a unique device ID
func (w *LinuxWiFiScanner) generateDeviceID(deviceType, identifier string) string {
	hash := md5.Sum([]byte(deviceType + ":" + identifier))
	return fmt.Sprintf("%x", hash)
}

// assessWiFiThreat performs threat assessment for WiFi devices
func (w *LinuxWiFiScanner) assessWiFiThreat(device *models.Device, scan *WiFiScanResult) int {
	threatLevel := 0
	
	// Hidden SSID is suspicious
	if device.Name == "" || device.Name == "<hidden>" {
		threatLevel += 2
	}
	
	// Very strong signal might indicate close surveillance equipment
	if device.SignalLevel > -30 {
		threatLevel += 2
	}
	
	// Suspicious SSID patterns
	suspiciousPatterns := []string{
		"camera", "cam", "spy", "hidden", "surveillance", "monitor",
		"watch", "security", "guard", "eye", "lens", "record",
		"wifi", "setup", "config", "admin", "test", "debug",
	}
	
	ssidLower := strings.ToLower(device.Name)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(ssidLower, pattern) {
			threatLevel += 3
			break
		}
	}
	
	// Open networks in unexpected places
	if scan.Encryption == "Open" && device.SignalLevel > -50 {
		threatLevel += 1
	}
	
	// Suspicious vendor combinations
	suspiciousVendors := []string{
		"unknown", "private", "anonymous",
	}
	
	vendorLower := strings.ToLower(device.Manufacturer)
	for _, vendor := range suspiciousVendors {
		if strings.Contains(vendorLower, vendor) {
			threatLevel += 1
			break
		}
	}
	
	// Default AP names from common surveillance equipment
	defaultNames := []string{
		"linksys", "netgear", "dlink", "default", "admin",
		"wifi", "wireless", "router", "modem",
	}
	
	for _, defaultName := range defaultNames {
		if strings.Contains(ssidLower, defaultName) && device.SignalLevel > -40 {
			threatLevel += 1
			break
		}
	}
	
	return threatLevel
}

// ScanChannels performs a scan on specific channels
func (w *LinuxWiFiScanner) ScanChannels(ctx context.Context, channels []int, duration time.Duration) ([]models.WiFiDevice, error) {
	// For now, perform a full scan and filter by channels
	devices, err := w.Scan(ctx, duration)
	if err != nil {
		return nil, err
	}
	
	wifiDevices := make([]models.WiFiDevice, 0)
	for _, device := range devices {
		// Check if device is on one of the requested channels
		for _, channel := range channels {
			if device.Channel == channel {
				wifiDevice := models.WiFiDevice{
					Device: device,
					SSID:   device.Name,
					BSSID:  device.MAC,
					Hidden: device.Name == "" || device.Name == "<hidden>",
				}
				wifiDevices = append(wifiDevices, wifiDevice)
				break
			}
		}
	}
	
	return wifiDevices, nil
}

// GetAvailableChannels returns available WiFi channels
func (w *LinuxWiFiScanner) GetAvailableChannels() []int {
	return w.config.Detection.WiFi.Channels
}

// IsAvailable checks if WiFi scanning is available
func (w *LinuxWiFiScanner) IsAvailable() bool {
	// Check if we have a wireless interface
	if w.iface == "" {
		return false
	}
	
	if _, err := exec.LookPath("iw"); err != nil {
		return false
	}
	
	return true
}

// GetType returns the scanner type
func (w *LinuxWiFiScanner) GetType() string {
	return "wifi"
}
