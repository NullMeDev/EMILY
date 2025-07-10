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
	"sync"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/models"
)

// LinuxCellularScanner implements cellular scanning for Linux systems
type LinuxCellularScanner struct {
	config  *config.Config
	running bool
}

// CellularScanResult represents a single cellular scan result
type CellularScanResult struct {
	CID           string // Cell ID
	LAC           string // Location Area Code
	MCC           string // Mobile Country Code
	MNC           string // Mobile Network Code
	RSSI          int    // Received Signal Strength Indicator
	Technology    string // GSM, UMTS, LTE, 5G
	Frequency     int    // Frequency in MHz
	Channel       int    // ARFCN/EARFCN
	Operator      string // Network operator name
	CellTowerInfo string // Additional cell tower information
}

// NewLinuxCellularScanner creates a new Linux cellular scanner
func NewLinuxCellularScanner(cfg *config.Config) (*LinuxCellularScanner, error) {
	scanner := &LinuxCellularScanner{
		config: cfg,
	}

	return scanner, nil
}

// Start starts the cellular scanner
func (c *LinuxCellularScanner) Start(ctx context.Context) error {
	c.running = true
	return nil
}

// Stop stops the cellular scanner
func (c *LinuxCellularScanner) Stop() error {
	c.running = false
	return nil
}

// Scan performs a cellular scan and returns detected cell towers
func (c *LinuxCellularScanner) Scan(ctx context.Context, duration time.Duration) ([]models.Device, error) {
	if !c.running {
		return nil, fmt.Errorf("scanner not running")
	}

	// Perform the actual cellular scan
	scanResults, err := c.performScan(ctx)
	if err != nil {
		return nil, fmt.Errorf("cellular scan failed: %w", err)
	}

	// Convert scan results to device models
	devices := make([]models.Device, 0, len(scanResults))
	now := time.Now()

	for _, result := range scanResults {
		device := models.Device{
			ID:           c.generateDeviceID("cellular", result.CID+result.LAC),
			Type:         "cellular",
			MAC:          "", // Cellular towers don't have MAC addresses
			Name:         c.getCellTowerName(&result),
			Manufacturer: result.Operator,
			SignalLevel:  result.RSSI,
			Channel:      result.Channel,
			Frequency:    result.Frequency,
			Encryption:   "N/A", // Cellular uses different security protocols
			FirstSeen:    now,
			LastSeen:     now,
			SeenCount:    1,
			CreatedAt:    now,
			UpdatedAt:    now,
		}

		// Assess potential threats
		device.ThreatLevel = c.assessCellularThreat(&device, &result)

		devices = append(devices, device)
	}

	return devices, nil
}

// performScan executes the actual cellular scan using various tools
func (c *LinuxCellularScanner) performScan(ctx context.Context) ([]CellularScanResult, error) {
	results := make([]CellularScanResult, 0)

	// Try ModemManager first (if available)
	if modemResults, err := c.scanWithModemManager(ctx); err == nil {
		results = append(results, modemResults...)
	}

	// Try AT commands via available modems
	if atResults, err := c.scanWithATCommands(ctx); err == nil {
		results = append(results, atResults...)
	}

	// Try network-manager for cellular info
	if nmResults, err := c.scanWithNetworkManager(ctx); err == nil {
		results = append(results, nmResults...)
	}

	// Try mmcli (ModemManager CLI) for detailed info
	if mmcliResults, err := c.scanWithMMCLI(ctx); err == nil {
		results = append(results, mmcliResults...)
	}

	return results, nil
}

// scanWithModemManager scans using ModemManager DBus interface
func (c *LinuxCellularScanner) scanWithModemManager(ctx context.Context) ([]CellularScanResult, error) {
	// Check if ModemManager is available
	cmd := exec.CommandContext(ctx, "systemctl", "is-active", "ModemManager")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ModemManager not available")
	}

	// Try to list modems
	cmd = exec.CommandContext(ctx, "mmcli", "-L")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list modems: %w", err)
	}

	return c.parseModemManagerOutput(string(output))
}

// scanWithATCommands scans using AT commands to available modems
func (c *LinuxCellularScanner) scanWithATCommands(ctx context.Context) ([]CellularScanResult, error) {
	// Look for available modem devices
	modemDevices := []string{
		"/dev/ttyUSB0", "/dev/ttyUSB1", "/dev/ttyUSB2",
		"/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyACM2",
		"/dev/ttyS0", "/dev/ttyS1",
	}

	results := make([]CellularScanResult, 0)

	for _, device := range modemDevices {
		if deviceResults, err := c.queryATCommands(ctx, device); err == nil {
			results = append(results, deviceResults...)
		}
	}

	return results, nil
}

// scanWithNetworkManager scans using NetworkManager
func (c *LinuxCellularScanner) scanWithNetworkManager(ctx context.Context) ([]CellularScanResult, error) {
	cmd := exec.CommandContext(ctx, "nmcli", "device", "show")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nmcli command failed: %w", err)
	}

	return c.parseNetworkManagerOutput(string(output))
}

// scanWithMMCLI scans using mmcli for detailed cellular information
func (c *LinuxCellularScanner) scanWithMMCLI(ctx context.Context) ([]CellularScanResult, error) {
	// First, get list of modems
	cmd := exec.CommandContext(ctx, "mmcli", "-L")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("mmcli list failed: %w", err)
	}

	modemNumbers := c.extractModemNumbers(string(output))
	results := make([]CellularScanResult, 0)

	for _, modemNum := range modemNumbers {
		if modemResults, err := c.queryModemDetails(ctx, modemNum); err == nil {
			results = append(results, modemResults...)
		}
	}

	return results, nil
}

// queryATCommands queries a specific modem device using AT commands
func (c *LinuxCellularScanner) queryATCommands(ctx context.Context, device string) ([]CellularScanResult, error) {
	// This is a simplified approach - in reality, you'd need proper serial communication
	// For now, we'll use a placeholder implementation
	return []CellularScanResult{}, nil
}

// parseModemManagerOutput parses ModemManager output
func (c *LinuxCellularScanner) parseModemManagerOutput(output string) ([]CellularScanResult, error) {
	results := make([]CellularScanResult, 0)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "/org/freedesktop/ModemManager1/Modem/") {
			// Extract modem path and query details
			// This would require more detailed implementation
		}
	}

	return results, nil
}

// parseNetworkManagerOutput parses NetworkManager output for cellular info
func (c *LinuxCellularScanner) parseNetworkManagerOutput(output string) ([]CellularScanResult, error) {
	results := make([]CellularScanResult, 0)
	lines := strings.Split(output, "\n")

	var currentResult *CellularScanResult
	
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for cellular device
		if strings.Contains(line, "GENERAL.TYPE:") && strings.Contains(line, "gsm") {
			currentResult = &CellularScanResult{
				Technology: "GSM",
			}
		}

		if currentResult == nil {
			continue
		}

		// Parse various cellular parameters
		if strings.Contains(line, "GENERAL.OPERATOR:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				currentResult.Operator = strings.TrimSpace(parts[1])
			}
		}

		// Signal strength
		if strings.Contains(line, "GENERAL.SIGNAL:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				if rssi, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					currentResult.RSSI = rssi
				}
			}
		}

		// Add completed result
		if strings.Contains(line, "GENERAL.DEVICE:") && currentResult != nil {
			results = append(results, *currentResult)
			currentResult = nil
		}
	}

	return results, nil
}

// extractModemNumbers extracts modem numbers from mmcli output
func (c *LinuxCellularScanner) extractModemNumbers(output string) []string {
	re := regexp.MustCompile(`/Modem/(\d+)`)
	matches := re.FindAllStringSubmatch(output, -1)
	
	numbers := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			numbers = append(numbers, match[1])
		}
	}
	
	return numbers
}

// queryModemDetails queries detailed information for a specific modem
func (c *LinuxCellularScanner) queryModemDetails(ctx context.Context, modemNum string) ([]CellularScanResult, error) {
	cmd := exec.CommandContext(ctx, "mmcli", "-m", modemNum)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("mmcli modem query failed: %w", err)
	}

	return c.parseMMCLIModemOutput(string(output))
}

// parseMMCLIModemOutput parses detailed modem information from mmcli
func (c *LinuxCellularScanner) parseMMCLIModemOutput(output string) ([]CellularScanResult, error) {
	result := CellularScanResult{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse various cellular parameters
		if strings.Contains(line, "operator name:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result.Operator = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "signal quality:") {
			re := regexp.MustCompile(`(\d+)%`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				if quality, err := strconv.Atoi(matches[1]); err == nil {
					// Convert percentage to approximate RSSI
					result.RSSI = -113 + (quality * 60 / 100)
				}
			}
		}

		if strings.Contains(line, "access technology:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				result.Technology = strings.TrimSpace(parts[1])
			}
		}

		// Cell ID and LAC would require more specific AT command queries
		// This is a simplified implementation
	}

	if result.Operator != "" {
		return []CellularScanResult{result}, nil
	}

	return []CellularScanResult{}, nil
}

// getCellTowerName generates a human-readable name for the cell tower
func (c *LinuxCellularScanner) getCellTowerName(result *CellularScanResult) string {
	if result.Operator != "" {
		return fmt.Sprintf("%s Tower (%s)", result.Operator, result.Technology)
	}
	
	if result.CID != "" {
		return fmt.Sprintf("Cell Tower %s", result.CID)
	}
	
	return "Unknown Cell Tower"
}

// generateDeviceID creates a unique device ID for cellular towers
func (c *LinuxCellularScanner) generateDeviceID(deviceType, identifier string) string {
	hash := md5.Sum([]byte(deviceType + ":" + identifier))
	return fmt.Sprintf("%x", hash)
}

// assessCellularThreat performs threat assessment for cellular devices
func (c *LinuxCellularScanner) assessCellularThreat(device *models.Device, scan *CellularScanResult) int {
	threatLevel := 0

	// Very strong signal from unknown operator might indicate IMSI catcher
	if device.SignalLevel > -60 && (scan.Operator == "" || scan.Operator == "Unknown") {
		threatLevel += 4
	}

	// Unusual or missing cell tower information
	if scan.CID == "" || scan.LAC == "" {
		threatLevel += 2
	}

	// Technology downgrade attacks (forcing to older, less secure protocols)
	if scan.Technology == "GSM" || scan.Technology == "2G" {
		threatLevel += 3 // GSM is more vulnerable to attacks
	}

	// Multiple towers with same operator but different characteristics might indicate spoofing
	// This would require more complex analysis comparing with historical data

	// Unusually strong signal (possible fake base station nearby)
	if device.SignalLevel > -50 {
		threatLevel += 2
	}

	// Suspicious operator names
	suspiciousOperators := []string{
		"test", "debug", "unknown", "private", "temp", "lab",
	}

	operatorLower := strings.ToLower(scan.Operator)
	for _, suspicious := range suspiciousOperators {
		if strings.Contains(operatorLower, suspicious) {
			threatLevel += 3
			break
		}
	}

	return threatLevel
}

// IsAvailable checks if cellular scanning is available
func (c *LinuxCellularScanner) IsAvailable() bool {
	// Check if any of the required tools are available
	tools := []string{"mmcli", "nmcli"}
	
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err == nil {
			return true
		}
	}

	// Check for modem devices
	modemDevices := []string{
		"/dev/ttyUSB0", "/dev/ttyACM0", "/dev/ttyS0",
	}

	for _, device := range modemDevices {
		if _, err := exec.Command("test", "-e", device).Output(); err == nil {
			return true
		}
	}

	return false
}

// GetCellInfo returns current cell tower information
func (c *LinuxCellularScanner) GetCellInfo() (*models.CellularDevice, error) {
	// Try to get current cell info using ModemManager
	cmd := exec.Command("mmcli", "-L")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get cell info: %w", err)
	}

	modemNumbers := c.extractModemNumbers(string(output))
	if len(modemNumbers) == 0 {
		return nil, fmt.Errorf("no modems found")
	}

	// Get info for the first available modem
	cmd = exec.Command("mmcli", "-m", modemNumbers[0])
	output, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to query modem: %w", err)
	}

	// Parse the output and create CellularDevice
	cellDevice := &models.CellularDevice{
		Operator: "Unknown",
		Technology: "Unknown",
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "operator name:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				cellDevice.Operator = strings.TrimSpace(parts[1])
			}
		}
		if strings.Contains(line, "access technology:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				cellDevice.Technology = strings.TrimSpace(parts[1])
			}
		}
	}

	return cellDevice, nil
}

// DetectIMSICatcher attempts to detect IMSI catcher presence
func (c *LinuxCellularScanner) DetectIMSICatcher() (bool, error) {
	// Advanced IMSI catcher detection with multiple indicators
	
	// Get current cell info
	cellInfo, err := c.GetCellInfo()
	if err != nil {
		return false, err
	}

	suspiciousIndicators := 0
	maxIndicators := 10

	// 1. Downgrade to 2G/GSM when 4G/LTE should be available
	if cellInfo.Technology == "GSM" || cellInfo.Technology == "2G" {
		suspiciousIndicators += 3 // High weight for technology downgrade
	}

	// 2. Unknown or suspicious operator names
	suspiciousOperators := []string{"test", "debug", "temp", "", "private", "lab", "research"}
	for _, suspicious := range suspiciousOperators {
		if strings.Contains(strings.ToLower(cellInfo.Operator), suspicious) {
			suspiciousIndicators += 2
			break
		}
	}

	// 3. Check for LAC (Location Area Code) anomalies
	if c.checkLACAnomaly() {
		suspiciousIndicators += 2
	}

	// 4. Check for rapid cell tower changes
	if c.checkRapidCellChanges() {
		suspiciousIndicators += 2
	}

	// 5. Check for unusual signal strength patterns
	if c.checkSignalAnomalies() {
		suspiciousIndicators += 1
	}

	// 6. Check for missing or invalid cell parameters
	if c.checkMissingCellParameters(cellInfo) {
		suspiciousIndicators += 1
	}

	// Return true if we have enough suspicious indicators
	return float64(suspiciousIndicators)/float64(maxIndicators) > 0.5, nil
}

// checkLACAnomaly detects Location Area Code anomalies
func (c *LinuxCellularScanner) checkLACAnomaly() bool {
	// Get current LAC values
	cmd := exec.Command("mmcli", "-L")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	modemNumbers := c.extractModemNumbers(string(output))
	if len(modemNumbers) == 0 {
		return false
	}

	// Query detailed modem info for LAC
	cmd = exec.Command("mmcli", "-m", modemNumbers[0], "--location-get")
	output, err = cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "lac:") {
			re := regexp.MustCompile(`lac: (\d+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				if lac, err := strconv.Atoi(matches[1]); err == nil {
					// Check for suspicious LAC values
					// LAC 0 or 65535 are often used by IMSI catchers
					if lac == 0 || lac == 65535 {
						return true
					}
					// LAC values outside typical ranges
					if lac < 1 || lac > 65534 {
						return true
					}
				}
			}
		}
	}
	return false
}

// CellHistory tracks cell tower connection history
type CellHistory struct {
	CellID    string
	LAC       string
	Timestamp time.Time
	RSSI      int
}

var cellHistory []CellHistory
var cellHistoryMutex sync.RWMutex

// checkRapidCellChanges detects rapid cell tower switching
func (c *LinuxCellularScanner) checkRapidCellChanges() bool {
	// Get current cell info
	cmd := exec.Command("mmcli", "-L")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	modemNumbers := c.extractModemNumbers(string(output))
	if len(modemNumbers) == 0 {
		return false
	}

	// Get current cell details
	cmd = exec.Command("mmcli", "-m", modemNumbers[0], "--location-get")
	output, err = cmd.Output()
	if err != nil {
		return false
	}

	var currentCell CellHistory
	currentCell.Timestamp = time.Now()

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "cell-id:") {
			re := regexp.MustCompile(`cell-id: (\d+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				currentCell.CellID = matches[1]
			}
		}
		if strings.Contains(line, "lac:") {
			re := regexp.MustCompile(`lac: (\d+)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				currentCell.LAC = matches[1]
			}
		}
	}

	// Add to history
	cellHistoryMutex.Lock()
	cellHistory = append(cellHistory, currentCell)
	// Keep only last 50 entries
	if len(cellHistory) > 50 {
		cellHistory = cellHistory[len(cellHistory)-50:]
	}
	cellHistoryMutex.Unlock()

	// Analyze for rapid changes
	cellHistoryMutex.RLock()
	defer cellHistoryMutex.RUnlock()

	if len(cellHistory) < 5 {
		return false
	}

	// Check for rapid switching in last 5 minutes
	recentChanges := 0
	fiveMinutesAgo := time.Now().Add(-5 * time.Minute)

	for i := len(cellHistory) - 1; i > 0; i-- {
		if cellHistory[i].Timestamp.Before(fiveMinutesAgo) {
			break
		}
		if cellHistory[i].CellID != cellHistory[i-1].CellID {
			recentChanges++
		}
	}

	// More than 3 cell changes in 5 minutes is suspicious
	return recentChanges > 3
}

// checkSignalAnomalies detects unusual signal patterns
func (c *LinuxCellularScanner) checkSignalAnomalies() bool {
	// Get current signal strength
	cmd := exec.Command("mmcli", "-L")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	modemNumbers := c.extractModemNumbers(string(output))
	if len(modemNumbers) == 0 {
		return false
	}

	cmd = exec.Command("mmcli", "-m", modemNumbers[0])
	output, err = cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "signal quality:") {
			re := regexp.MustCompile(`(\d+)%`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				if quality, err := strconv.Atoi(matches[1]); err == nil {
					// Convert to approximate RSSI
					rssi := -113 + (quality * 60 / 100)
					
					// IMSI catchers often have very strong signals
					if rssi > -40 {
						return true // Unusually strong signal
					}
					
					// Check for perfect signal (100%) which is suspicious
					if quality == 100 {
						return true
					}
				}
			}
		}
	}

	// Check signal strength history for sudden changes
	cellHistoryMutex.RLock()
	defer cellHistoryMutex.RUnlock()

	if len(cellHistory) >= 3 {
		// Check for sudden signal strength jumps
		recent := cellHistory[len(cellHistory)-3:]
		for i := 1; i < len(recent); i++ {
			rssiDiff := recent[i].RSSI - recent[i-1].RSSI
			if rssiDiff > 20 || rssiDiff < -20 {
				// Sudden 20dB change is suspicious
				return true
			}
		}
	}

	return false
}

// checkMissingCellParameters checks for incomplete cell information
func (c *LinuxCellularScanner) checkMissingCellParameters(cellInfo *models.CellularDevice) bool {
	// IMSI catchers often don't provide complete cell information
	return cellInfo.Operator == "" || cellInfo.Technology == ""
}

// GetType returns the scanner type
func (c *LinuxCellularScanner) GetType() string {
	return "cellular"
}
