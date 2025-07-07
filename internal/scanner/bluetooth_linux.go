//go:build linux
// +build linux

package scanner

import (
	"context"
	"crypto/md5"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/models"
)

// LinuxBluetoothScanner implements Bluetooth scanning for Linux systems
type LinuxBluetoothScanner struct {
	config  *config.Config
	running bool
}

// BluetoothScanResult represents a single Bluetooth scan result
type BluetoothScanResult struct {
	Address      string
	Name         string
	Class        int
	RSSI         int
	TxPower      int
	Services     []string
	IsLE         bool
	IsConnected  bool
	AdvData      map[string]string
	Manufacturer string
}

// NewLinuxBluetoothScanner creates a new Linux Bluetooth scanner
func NewLinuxBluetoothScanner(cfg *config.Config) (*LinuxBluetoothScanner, error) {
	scanner := &LinuxBluetoothScanner{
		config: cfg,
	}

	return scanner, nil
}

// Start starts the Bluetooth scanner
func (b *LinuxBluetoothScanner) Start(ctx context.Context) error {
	b.running = true
	
	// Enable Bluetooth scanning if not already enabled
	if err := b.enableBluetoothScan(); err != nil {
		return fmt.Errorf("failed to enable Bluetooth scanning: %w", err)
	}
	
	return nil
}

// Stop stops the Bluetooth scanner
func (b *LinuxBluetoothScanner) Stop() error {
	b.running = false
	return nil
}

// Scan performs a Bluetooth scan and returns detected devices
func (b *LinuxBluetoothScanner) Scan(ctx context.Context, duration time.Duration) ([]models.Device, error) {
	if !b.running {
		return nil, fmt.Errorf("scanner not running")
	}

	// Perform the actual Bluetooth scan
	scanResults, err := b.performScan(ctx, duration)
	if err != nil {
		return nil, fmt.Errorf("scan failed: %w", err)
	}

	// Convert scan results to device models
	devices := make([]models.Device, 0, len(scanResults))
	now := time.Now()

	for _, result := range scanResults {
		device := models.Device{
			ID:           b.generateDeviceID("bluetooth", result.Address),
			Type:         "bluetooth",
			MAC:          result.Address,
			Name:         result.Name,
			Manufacturer: result.Manufacturer,
			SignalLevel:  result.RSSI,
			FirstSeen:    now,
			LastSeen:     now,
			SeenCount:    1,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		// Assess potential threats
		device.ThreatLevel = b.assessBluetoothThreat(&device, &result)

		devices = append(devices, device)
	}

	return devices, nil
}

// enableBluetoothScan enables Bluetooth scanning
func (b *LinuxBluetoothScanner) enableBluetoothScan() error {
	// Check if Bluetooth is powered on
	cmd := exec.Command("bluetoothctl", "show")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to check Bluetooth status: %w", err)
	}

	if !strings.Contains(string(output), "Powered: yes") {
		// Try to power on Bluetooth
		cmd = exec.Command("bluetoothctl", "power", "on")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to power on Bluetooth: %w", err)
		}
		
		// Wait a moment for Bluetooth to initialize
		time.Sleep(2 * time.Second)
	}

	return nil
}

// performScan executes the actual Bluetooth scan
func (b *LinuxBluetoothScanner) performScan(ctx context.Context, duration time.Duration) ([]BluetoothScanResult, error) {
	// Use hcitool for scanning (classic Bluetooth)
	classicResults, err := b.performClassicScan(ctx, duration)
	if err != nil {
		fmt.Printf("Classic Bluetooth scan failed: %v\n", err)
		classicResults = []BluetoothScanResult{}
	}

	// Use bluetoothctl for BLE scanning
	bleResults, err := b.performBLEScan(ctx, duration)
	if err != nil {
		fmt.Printf("BLE scan failed: %v\n", err)
		bleResults = []BluetoothScanResult{}
	}

	// Combine results
	allResults := append(classicResults, bleResults...)
	
	// Remove duplicates based on MAC address
	uniqueResults := make([]BluetoothScanResult, 0)
	seen := make(map[string]bool)
	
	for _, result := range allResults {
		if !seen[result.Address] {
			seen[result.Address] = true
			uniqueResults = append(uniqueResults, result)
		}
	}

	return uniqueResults, nil
}

// performClassicScan scans for classic Bluetooth devices
func (b *LinuxBluetoothScanner) performClassicScan(ctx context.Context, duration time.Duration) ([]BluetoothScanResult, error) {
	// Use hcitool scan for device discovery
	timeoutCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "hcitool", "scan", "--info")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to simple scan
		cmd = exec.CommandContext(timeoutCtx, "hcitool", "scan")
		output, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("hcitool scan failed: %w", err)
		}
	}

	return b.parseHcitoolOutput(string(output))
}

// performBLEScan scans for Bluetooth Low Energy devices
func (b *LinuxBluetoothScanner) performBLEScan(ctx context.Context, duration time.Duration) ([]BluetoothScanResult, error) {
	// Start scanning with bluetoothctl
	startCmd := exec.Command("bluetoothctl", "scan", "on")
	if err := startCmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to start BLE scan: %w", err)
	}

	// Wait for the scan duration
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(duration):
		// Continue with processing
	}

	// Stop scanning
	stopCmd := exec.Command("bluetoothctl", "scan", "off")
	stopCmd.Run() // Ignore errors here

	// Get discovered devices
	cmd := exec.Command("bluetoothctl", "devices")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get BLE devices: %w", err)
	}

	return b.parseBluetoothctlOutput(string(output))
}

// parseHcitoolOutput parses the output from hcitool scan
func (b *LinuxBluetoothScanner) parseHcitoolOutput(output string) ([]BluetoothScanResult, error) {
	results := make([]BluetoothScanResult, 0)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "Scanning") {
			continue
		}

		// Parse format: "XX:XX:XX:XX:XX:XX    Device Name"
		re := regexp.MustCompile(`([0-9A-Fa-f:]{17})\s+(.*)`)
		if matches := re.FindStringSubmatch(line); len(matches) > 2 {
			result := BluetoothScanResult{
				Address:      strings.ToLower(matches[1]),
				Name:         strings.TrimSpace(matches[2]),
				IsLE:         false,
				Manufacturer: b.getVendorFromMAC(matches[1]),
			}

			// Try to get additional info for this device
			if info := b.getDeviceInfo(result.Address); info != nil {
				result.Class = info.Class
				result.RSSI = info.RSSI
			}

			results = append(results, result)
		}
	}

	return results, nil
}

// parseBluetoothctlOutput parses the output from bluetoothctl devices
func (b *LinuxBluetoothScanner) parseBluetoothctlOutput(output string) ([]BluetoothScanResult, error) {
	results := make([]BluetoothScanResult, 0)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "Device ") {
			continue
		}

		// Parse format: "Device XX:XX:XX:XX:XX:XX Device Name"
		re := regexp.MustCompile(`Device ([0-9A-Fa-f:]{17})\s+(.*)`)
		if matches := re.FindStringSubmatch(line); len(matches) > 2 {
			result := BluetoothScanResult{
				Address:      strings.ToLower(matches[1]),
				Name:         strings.TrimSpace(matches[2]),
				IsLE:         true,
				Manufacturer: b.getVendorFromMAC(matches[1]),
			}

			// Try to get additional info for this device
			if info := b.getDeviceInfo(result.Address); info != nil {
				result.RSSI = info.RSSI
				result.TxPower = info.TxPower
				result.Services = info.Services
			}

			results = append(results, result)
		}
	}

	return results, nil
}

// getDeviceInfo gets additional information about a Bluetooth device
func (b *LinuxBluetoothScanner) getDeviceInfo(address string) *BluetoothScanResult {
	cmd := exec.Command("bluetoothctl", "info", address)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	info := &BluetoothScanResult{}
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "RSSI:") {
			if rssi, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "RSSI:"))); err == nil {
				info.RSSI = rssi
			}
		}

		if strings.HasPrefix(line, "TxPower:") {
			if txPower, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "TxPower:"))); err == nil {
				info.TxPower = txPower
			}
		}

		if strings.HasPrefix(line, "Class:") {
			classStr := strings.TrimSpace(strings.TrimPrefix(line, "Class:"))
			if class, err := strconv.ParseInt(classStr, 0, 32); err == nil {
				info.Class = int(class)
			}
		}

		if strings.Contains(line, "UUID:") {
			re := regexp.MustCompile(`UUID: ([0-9a-fA-F-]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				info.Services = append(info.Services, matches[1])
			}
		}
	}

	return info
}

// getVendorFromMAC attempts to identify the vendor from MAC address
func (b *LinuxBluetoothScanner) getVendorFromMAC(mac string) string {
	if len(mac) < 8 {
		return "Unknown"
	}

	// Extract OUI (first 3 octets)
	oui := strings.ReplaceAll(mac[:8], ":", "")
	oui = strings.ToUpper(oui)

	// Common Bluetooth OUI mappings
	ouiMap := map[string]string{
		"001122": "Apple",
		"A45E60": "Apple",
		"8863DF": "Apple",
		"40B395": "Samsung",
		"E8E5D6": "Samsung",
		"B4F61C": "Samsung",
		"000F3D": "Broadcom",
		"AC220B": "Broadcom",
		"001B63": "Intel",
		"7C7A91": "Intel",
		"00E04C": "Realtek",
		"001E2A": "Cisco",
		"001CF0": "D-Link",
		"0018E7": "Netgear",
		"00226B": "Sony",
		"001A7D": "Sony",
		"A020A6": "Sony",
		"B8F009": "Bose",
		"04F021": "Bose",
		"00259C": "Microsoft",
		"7C1E52": "Microsoft",
	}

	if vendor, exists := ouiMap[oui]; exists {
		return vendor
	}

	return "Unknown"
}

// generateDeviceID creates a unique device ID
func (b *LinuxBluetoothScanner) generateDeviceID(deviceType, identifier string) string {
	hash := md5.Sum([]byte(deviceType + ":" + identifier))
	return fmt.Sprintf("%x", hash)
}

// assessBluetoothThreat performs threat assessment for Bluetooth devices
func (b *LinuxBluetoothScanner) assessBluetoothThreat(device *models.Device, scan *BluetoothScanResult) int {
	threatLevel := 0

	// Anonymous or no name can be suspicious
	if device.Name == "" || device.Name == "Unknown" {
		threatLevel += 1
	}

	// Very strong signal might indicate tracking device nearby
	if device.SignalLevel > -30 {
		threatLevel += 2
	}

	// Check for suspicious device names
	suspiciousNames := []string{
		"tracker", "tag", "beacon", "spy", "hidden", "surveillance",
		"monitor", "camera", "audio", "record", "listening",
	}

	nameLower := strings.ToLower(device.Name)
	for _, suspicious := range suspiciousNames {
		if strings.Contains(nameLower, suspicious) {
			threatLevel += 4
			break
		}
	}

	// Check for tracking device patterns (like AirTags, Tile, etc.)
	trackingPatterns := []string{
		"airtag", "tile", "chipolo", "samsung tag", "galaxy tag",
		"tracker", "find my", "findmy", "smarttag",
	}

	for _, pattern := range trackingPatterns {
		if strings.Contains(nameLower, pattern) {
			threatLevel += 3
			break
		}
	}

	// BLE devices with very short names might be suspicious
	if scan.IsLE && len(device.Name) <= 3 && device.Name != "" {
		threatLevel += 1
	}

	// Unknown manufacturer with strong signal
	if device.Manufacturer == "Unknown" && device.SignalLevel > -40 {
		threatLevel += 1
	}

	return threatLevel
}

// ScanLE performs a BLE-specific scan
func (b *LinuxBluetoothScanner) ScanLE(ctx context.Context, duration time.Duration) ([]models.BluetoothDevice, error) {
	results, err := b.performBLEScan(ctx, duration)
	if err != nil {
		return nil, err
	}

	devices := make([]models.BluetoothDevice, 0, len(results))
	now := time.Now()

	for _, result := range results {
		device := models.BluetoothDevice{
			Device: models.Device{
				ID:           b.generateDeviceID("bluetooth", result.Address),
				Type:         "bluetooth",
				MAC:          result.Address,
				Name:         result.Name,
				Manufacturer: result.Manufacturer,
				SignalLevel:  result.RSSI,
				FirstSeen:    now,
				LastSeen:     now,
				SeenCount:    1,
				CreatedAt:    now,
				UpdatedAt:    now,
			},
			Address:       result.Address,
			Class:         strconv.Itoa(result.Class),
			Services:      result.Services,
			IsLE:          result.IsLE,
			TxPower:       result.TxPower,
			RSSI:          result.RSSI,
			Connected:     result.IsConnected,
			Advertisement: result.AdvData,
		}

		device.ThreatLevel = b.assessBluetoothThreat(&device.Device, &result)
		devices = append(devices, device)
	}

	return devices, nil
}

// ScanClassic performs a classic Bluetooth scan
func (b *LinuxBluetoothScanner) ScanClassic(ctx context.Context, duration time.Duration) ([]models.BluetoothDevice, error) {
	results, err := b.performClassicScan(ctx, duration)
	if err != nil {
		return nil, err
	}

	devices := make([]models.BluetoothDevice, 0, len(results))
	now := time.Now()

	for _, result := range results {
		device := models.BluetoothDevice{
			Device: models.Device{
				ID:           b.generateDeviceID("bluetooth", result.Address),
				Type:         "bluetooth",
				MAC:          result.Address,
				Name:         result.Name,
				Manufacturer: result.Manufacturer,
				SignalLevel:  result.RSSI,
				FirstSeen:    now,
				LastSeen:     now,
				SeenCount:    1,
				CreatedAt:    now,
				UpdatedAt:    now,
			},
			Address:       result.Address,
			Class:         strconv.Itoa(result.Class),
			Services:      result.Services,
			IsLE:          result.IsLE,
			TxPower:       result.TxPower,
			RSSI:          result.RSSI,
			Connected:     result.IsConnected,
			Advertisement: result.AdvData,
		}

		device.ThreatLevel = b.assessBluetoothThreat(&device.Device, &result)
		devices = append(devices, device)
	}

	return devices, nil
}

// IsAvailable checks if Bluetooth scanning is available
func (b *LinuxBluetoothScanner) IsAvailable() bool {
	// Check if we have bluetoothctl
	if _, err := exec.LookPath("bluetoothctl"); err != nil {
		return false
	}

	// Check if we have hcitool for classic scanning
	if _, err := exec.LookPath("hcitool"); err != nil {
		// Still available with just bluetoothctl for BLE
	}

	// Check if Bluetooth adapter is present
	cmd := exec.Command("bluetoothctl", "list")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), "Controller")
}

// GetType returns the scanner type
func (b *LinuxBluetoothScanner) GetType() string {
	return "bluetooth"
}
