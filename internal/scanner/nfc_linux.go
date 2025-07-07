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

// LinuxNFCScanner implements NFC scanning for Linux systems
type LinuxNFCScanner struct {
	config  *config.Config
	running bool
}

// NFCScanResult represents a single NFC scan result
type NFCScanResult struct {
	UID           string // Unique identifier
	Type          string // Tag type (MIFARE, NTAG, etc.)
	Technology    string // NFC technology (A, B, F)
	ATQA          string // Answer to request type A
	SAK           string // Select acknowledge
	ATS           string // Answer to select
	SystemCode    string // System code (for Type F)
	PMm           string // Manufacture parameter (for Type F)
	ApplicationID string // Application identifier
	DataSize      int    // Available data size
	IsReadable    bool   // Whether tag is readable
	IsWriteable   bool   // Whether tag is writeable
	HasData       bool   // Whether tag contains data
}

// NewLinuxNFCScanner creates a new Linux NFC scanner
func NewLinuxNFCScanner(cfg *config.Config) (*LinuxNFCScanner, error) {
	scanner := &LinuxNFCScanner{
		config: cfg,
	}

	return scanner, nil
}

// Start starts the NFC scanner
func (n *LinuxNFCScanner) Start(ctx context.Context) error {
	n.running = true
	return nil
}

// Stop stops the NFC scanner
func (n *LinuxNFCScanner) Stop() error {
	n.running = false
	return nil
}

// Scan performs an NFC scan and returns detected devices/tags
func (n *LinuxNFCScanner) Scan(ctx context.Context, duration time.Duration) ([]models.Device, error) {
	if !n.running {
		return nil, fmt.Errorf("scanner not running")
	}

	// Perform the actual NFC scan
	scanResults, err := n.performScan(ctx, duration)
	if err != nil {
		return nil, fmt.Errorf("NFC scan failed: %w", err)
	}

	// Convert scan results to device models
	devices := make([]models.Device, 0, len(scanResults))
	now := time.Now()

	for _, result := range scanResults {
		device := models.Device{
			ID:           n.generateDeviceID("nfc", result.UID),
			Type:         "nfc",
			MAC:          result.UID, // Use UID as identifier
			Name:         n.getNFCDeviceName(&result),
			Manufacturer: n.getManufacturerFromUID(result.UID),
			SignalLevel:  0, // NFC doesn't have traditional signal strength
			Channel:      0, // NFC operates on 13.56 MHz
			Frequency:    13560000, // 13.56 MHz in Hz
			Encryption:   n.getEncryptionInfo(&result),
			FirstSeen:    now,
			LastSeen:     now,
			SeenCount:    1,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		// Assess potential threats
		device.ThreatLevel = n.assessNFCThreat(&device, &result)

		devices = append(devices, device)
	}

	return devices, nil
}

// performScan executes the actual NFC scan using various tools
func (n *LinuxNFCScanner) performScan(ctx context.Context, duration time.Duration) ([]NFCScanResult, error) {
	results := make([]NFCScanResult, 0)

	// Try nfc-list first (part of libnfc)
	if nfcResults, err := n.scanWithNFCList(ctx, duration); err == nil {
		results = append(results, nfcResults...)
	}

	// Try nfc-poll for polling mode
	if pollResults, err := n.scanWithNFCPoll(ctx, duration); err == nil {
		results = append(results, pollResults...)
	}

	// Try Android Debug Bridge for connected Android devices with NFC
	if adbResults, err := n.scanWithADB(ctx); err == nil {
		results = append(results, adbResults...)
	}

	return results, nil
}

// scanWithNFCList scans using nfc-list command
func (n *LinuxNFCScanner) scanWithNFCList(ctx context.Context, duration time.Duration) ([]NFCScanResult, error) {
	// Create a context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "nfc-list")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nfc-list command failed: %w", err)
	}

	return n.parseNFCListOutput(string(output))
}

// scanWithNFCPoll scans using nfc-poll command for active polling
func (n *LinuxNFCScanner) scanWithNFCPoll(ctx context.Context, duration time.Duration) ([]NFCScanResult, error) {
	// Create a context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	// Poll for a specific duration (convert to seconds)
	durationSeconds := int(duration.Seconds())
	if durationSeconds < 1 {
		durationSeconds = 1
	}

	cmd := exec.CommandContext(timeoutCtx, "nfc-poll", "-t", strconv.Itoa(durationSeconds))
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nfc-poll command failed: %w", err)
	}

	return n.parseNFCPollOutput(string(output))
}

// scanWithADB scans NFC capabilities of connected Android devices
func (n *LinuxNFCScanner) scanWithADB(ctx context.Context) ([]NFCScanResult, error) {
	// Check if ADB is available and devices are connected
	cmd := exec.CommandContext(ctx, "adb", "devices")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("adb command failed: %w", err)
	}

	// If no devices, return empty
	if !strings.Contains(string(output), "device") {
		return []NFCScanResult{}, nil
	}

	// Try to get NFC status from connected Android device
	cmd = exec.CommandContext(ctx, "adb", "shell", "dumpsys", "nfc")
	output, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("adb nfc dumpsys failed: %w", err)
	}

	return n.parseADBNFCOutput(string(output))
}

// parseNFCListOutput parses output from nfc-list command
func (n *LinuxNFCScanner) parseNFCListOutput(output string) ([]NFCScanResult, error) {
	results := make([]NFCScanResult, 0)
	lines := strings.Split(output, "\n")

	var currentResult *NFCScanResult

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// New NFC target found
		if strings.Contains(line, "NFC device:") || strings.Contains(line, "NFC target:") {
			if currentResult != nil {
				results = append(results, *currentResult)
			}
			currentResult = &NFCScanResult{}
		}

		if currentResult == nil {
			continue
		}

		// Parse UID
		if strings.Contains(line, "UID:") || strings.Contains(line, "NFCID") {
			re := regexp.MustCompile(`(?:UID|NFCID[^:]*): *([0-9a-fA-F ]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				uid := strings.ReplaceAll(matches[1], " ", "")
				currentResult.UID = strings.ToLower(uid)
			}
		}

		// Parse ATQA
		if strings.Contains(line, "ATQA:") {
			re := regexp.MustCompile(`ATQA: *([0-9a-fA-F ]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				currentResult.ATQA = strings.TrimSpace(matches[1])
			}
		}

		// Parse SAK
		if strings.Contains(line, "SAK:") {
			re := regexp.MustCompile(`SAK: *([0-9a-fA-F]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				currentResult.SAK = strings.TrimSpace(matches[1])
			}
		}

		// Parse card type
		if strings.Contains(line, "Mifare") {
			currentResult.Type = "MIFARE"
		} else if strings.Contains(line, "NTAG") {
			currentResult.Type = "NTAG"
		} else if strings.Contains(line, "Type A") {
			currentResult.Technology = "A"
		} else if strings.Contains(line, "Type B") {
			currentResult.Technology = "B"
		} else if strings.Contains(line, "Type F") || strings.Contains(line, "FeliCa") {
			currentResult.Technology = "F"
		}

		// Check for data availability
		if strings.Contains(line, "readable") {
			currentResult.IsReadable = true
			currentResult.HasData = true
		}
		if strings.Contains(line, "writable") {
			currentResult.IsWriteable = true
		}
	}

	// Add the last result
	if currentResult != nil {
		results = append(results, *currentResult)
	}

	return results, nil
}

// parseNFCPollOutput parses output from nfc-poll command
func (n *LinuxNFCScanner) parseNFCPollOutput(output string) ([]NFCScanResult, error) {
	results := make([]NFCScanResult, 0)
	lines := strings.Split(output, "\n")

	var currentResult *NFCScanResult

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// New target detected
		if strings.Contains(line, "Target:") || strings.Contains(line, "Found tag") {
			if currentResult != nil {
				results = append(results, *currentResult)
			}
			currentResult = &NFCScanResult{}
		}

		if currentResult == nil {
			continue
		}

		// Similar parsing logic as nfc-list but adapted for poll output format
		if strings.Contains(line, "UID") || strings.Contains(line, "NFCID") {
			re := regexp.MustCompile(`(?:UID|NFCID[^:]*)[^0-9a-fA-F]*([0-9a-fA-F ]+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				uid := strings.ReplaceAll(matches[1], " ", "")
				currentResult.UID = strings.ToLower(uid)
			}
		}

		// Technology detection
		if strings.Contains(line, "ISO14443 Type A") {
			currentResult.Technology = "A"
		} else if strings.Contains(line, "ISO14443 Type B") {
			currentResult.Technology = "B"
		} else if strings.Contains(line, "JIS X 6319-4") || strings.Contains(line, "FeliCa") {
			currentResult.Technology = "F"
		}
	}

	// Add the last result
	if currentResult != nil {
		results = append(results, *currentResult)
	}

	return results, nil
}

// parseADBNFCOutput parses NFC information from Android ADB
func (n *LinuxNFCScanner) parseADBNFCOutput(output string) ([]NFCScanResult, error) {
	results := make([]NFCScanResult, 0)
	lines := strings.Split(output, "\n")

	result := NFCScanResult{
		Type:       "Android NFC",
		Technology: "Device",
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check if NFC is enabled
		if strings.Contains(line, "NFC Enabled:") && strings.Contains(line, "true") {
			result.HasData = true
		}

		// Extract NFC chip information if available
		if strings.Contains(line, "Chipset:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result.Type = strings.TrimSpace(parts[1])
			}
		}
	}

	if result.HasData {
		// Generate a pseudo-UID for the Android device
		result.UID = "android_nfc_device"
		results = append(results, result)
	}

	return results, nil
}

// getNFCDeviceName generates a human-readable name for the NFC device
func (n *LinuxNFCScanner) getNFCDeviceName(result *NFCScanResult) string {
	if result.Type != "" {
		if result.Technology != "" {
			return fmt.Sprintf("%s Tag (Type %s)", result.Type, result.Technology)
		}
		return fmt.Sprintf("%s Tag", result.Type)
	}

	if result.Technology != "" {
		return fmt.Sprintf("NFC Type %s Tag", result.Technology)
	}

	if result.UID != "" {
		return fmt.Sprintf("NFC Tag %s", result.UID[:8])
	}

	return "Unknown NFC Device"
}

// getManufacturerFromUID attempts to identify manufacturer from UID
func (n *LinuxNFCScanner) getManufacturerFromUID(uid string) string {
	if len(uid) < 2 {
		return "Unknown"
	}

	// First byte of UID can indicate manufacturer for some tags
	// This is a simplified mapping
	firstByte := strings.ToUpper(uid[:2])

	manufacturerMap := map[string]string{
		"04": "NXP",
		"02": "STMicroelectronics", 
		"05": "Infineon",
		"06": "Cypress",
		"07": "Texas Instruments",
		"08": "Fujitsu",
		"09": "Matsushita",
		"0A": "NEC",
		"0B": "Oki Electric",
		"0C": "Toshiba",
		"0D": "Mitsubishi",
		"0E": "Samsung",
		"0F": "Hynix",
	}

	if manufacturer, exists := manufacturerMap[firstByte]; exists {
		return manufacturer
	}

	return "Unknown"
}

// getEncryptionInfo determines encryption/security information
func (n *LinuxNFCScanner) getEncryptionInfo(result *NFCScanResult) string {
	// Basic security assessment based on tag type
	switch result.Type {
	case "MIFARE":
		return "CRYPTO1" // MIFARE Classic uses CRYPTO1
	case "NTAG":
		return "AES" // NTAG series can support AES
	default:
		if result.IsWriteable && result.IsReadable {
			return "None"
		}
		return "Unknown"
	}
}

// generateDeviceID creates a unique device ID for NFC devices
func (n *LinuxNFCScanner) generateDeviceID(deviceType, identifier string) string {
	hash := md5.Sum([]byte(deviceType + ":" + identifier))
	return fmt.Sprintf("%x", hash)
}

// assessNFCThreat performs threat assessment for NFC devices
func (n *LinuxNFCScanner) assessNFCThreat(device *models.Device, scan *NFCScanResult) int {
	threatLevel := 0

	// Writeable tags could be used for malicious purposes
	if scan.IsWriteable {
		threatLevel += 2
	}

	// Tags with data that are also writeable are higher risk
	if scan.HasData && scan.IsWriteable {
		threatLevel += 2
	}

	// Unusual or suspicious tag types
	if scan.Type == "" || scan.UID == "" {
		threatLevel += 1
	}

	// Very short UIDs might indicate cloned or malicious tags
	if len(scan.UID) < 8 {
		threatLevel += 1
	}

	// Android devices with NFC enabled could be used for attacks
	if scan.Type == "Android NFC" {
		threatLevel += 1
	}

	// Unencrypted, writeable tags are potential security risks
	if device.Encryption == "None" && scan.IsWriteable {
		threatLevel += 2
	}

	// Known vulnerable encryption (CRYPTO1 is weak)
	if device.Encryption == "CRYPTO1" {
		threatLevel += 1
	}

	return threatLevel
}

// IsAvailable checks if NFC scanning is available
func (n *LinuxNFCScanner) IsAvailable() bool {
	// Check if libnfc tools are available
	tools := []string{"nfc-list", "nfc-poll"}
	
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err == nil {
			return true
		}
	}

	// Check if ADB is available (for Android NFC scanning)
	if _, err := exec.LookPath("adb"); err == nil {
		return true
	}

	// Check for NFC device files
	nfcDevices := []string{
		"/dev/nfc0", "/dev/nfc1",
	}

	for _, device := range nfcDevices {
		if _, err := exec.Command("test", "-e", device).Output(); err == nil {
			return true
		}
	}

	return false
}

// ScanTags performs NFC tag scanning and returns structured NFC devices
func (n *LinuxNFCScanner) ScanTags(ctx context.Context, duration time.Duration) ([]models.NFCDevice, error) {
	// Get general devices first
	devices, err := n.Scan(ctx, duration)
	if err != nil {
		return nil, err
	}

	// Convert to NFCDevice format
	nfcDevices := make([]models.NFCDevice, 0, len(devices))
	for _, device := range devices {
		nfcDevice := models.NFCDevice{
			Device: device,
			UID: device.MAC, // Using MAC field as UID
			TagType: "Unknown", // Would need to extract from scan results
		}

		// Try to determine tag type from device name
		if strings.Contains(device.Name, "MIFARE") {
			nfcDevice.TagType = "MIFARE"
		} else if strings.Contains(device.Name, "NTAG") {
			nfcDevice.TagType = "NTAG"
		} else if strings.Contains(device.Name, "Type A") {
			nfcDevice.TagType = "ISO14443-A"
		} else if strings.Contains(device.Name, "Type B") {
			nfcDevice.TagType = "ISO14443-B"
		} else if strings.Contains(device.Name, "Type F") {
			nfcDevice.TagType = "FeliCa"
		}

		nfcDevices = append(nfcDevices, nfcDevice)
	}

	return nfcDevices, nil
}

// IsNFCEnabled checks if NFC functionality is enabled
func (n *LinuxNFCScanner) IsNFCEnabled() bool {
	// Check if NFC tools are available and working
	tools := []string{"nfc-list", "nfc-poll"}
	
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err == nil {
			// Try a quick test to see if NFC is actually working
			cmd := exec.Command(tool, "--help")
			if err := cmd.Run(); err == nil {
				return true
			}
		}
	}

	// Check for NFC devices in /dev
	nfcDevices := []string{"/dev/nfc0", "/dev/nfc1"}
	for _, device := range nfcDevices {
		if _, err := exec.Command("test", "-e", device).Output(); err == nil {
			return true
		}
	}

	// Check if Android ADB has NFC-enabled devices
	if _, err := exec.LookPath("adb"); err == nil {
		cmd := exec.Command("adb", "devices")
		if output, err := cmd.Output(); err == nil {
			if strings.Contains(string(output), "device") {
				return true // Assume Android device might have NFC
			}
		}
	}

	return false
}

// GetType returns the scanner type
func (n *LinuxNFCScanner) GetType() string {
	return "nfc"
}
