package android

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/models"
)

// HardwareManager manages Android hardware integration
type HardwareManager struct {
	config      *config.Config
	isAndroid   bool
	adbEnabled  bool
	deviceID    string
	permissions map[string]bool
}

// AndroidDevice represents an Android device and its capabilities
type AndroidDevice struct {
	ID           string            `json:"id"`
	Model        string            `json:"model"`
	Manufacturer string            `json:"manufacturer"`
	AndroidVersion string          `json:"android_version"`
	BuildNumber  string            `json:"build_number"`
	Capabilities map[string]bool   `json:"capabilities"`
	Sensors      []AndroidSensor   `json:"sensors"`
	NetworkInfo  *AndroidNetworkInfo `json:"network_info"`
}

// AndroidSensor represents a device sensor
type AndroidSensor struct {
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Vendor      string  `json:"vendor"`
	Version     int     `json:"version"`
	MaxRange    float64 `json:"max_range"`
	Resolution  float64 `json:"resolution"`
	Power       float64 `json:"power"`
	Available   bool    `json:"available"`
}

// AndroidNetworkInfo represents network information from Android
type AndroidNetworkInfo struct {
	WiFiEnabled     bool     `json:"wifi_enabled"`
	BluetoothEnabled bool    `json:"bluetooth_enabled"`
	NFCEnabled      bool     `json:"nfc_enabled"`
	CellularEnabled bool     `json:"cellular_enabled"`
	ConnectedSSID   string   `json:"connected_ssid"`
	SignalStrength  int      `json:"signal_strength"`
	NetworkType     string   `json:"network_type"`
	MobileOperator  string   `json:"mobile_operator"`
	BluetoothMAC    string   `json:"bluetooth_mac"`
	WiFiMAC         string   `json:"wifi_mac"`
}

// NewHardwareManager creates a new Android hardware manager
func NewHardwareManager(cfg *config.Config) (*HardwareManager, error) {
	hm := &HardwareManager{
		config:      cfg,
		permissions: make(map[string]bool),
	}

	// Detect if we're running on Android
	hm.isAndroid = hm.detectAndroid()
	
	// Check ADB availability
	hm.adbEnabled = hm.checkADBAvailability()

	if hm.adbEnabled {
		hm.deviceID = hm.getConnectedDevice()
	}

	return hm, nil
}

// detectAndroid checks if we're running on Android
func (hm *HardwareManager) detectAndroid() bool {
	// Check for Android-specific files and properties
	androidIndicators := []string{
		"/system/build.prop",
		"/system/bin/getprop",
		"/proc/version",
	}

	for _, indicator := range androidIndicators {
		if cmd := exec.Command("test", "-e", indicator); cmd.Run() == nil {
			return true
		}
	}

	// Check via getprop if available
	if cmd := exec.Command("getprop", "ro.build.version.release"); cmd.Run() == nil {
		return true
	}

	return false
}

// checkADBAvailability checks if ADB is available and working
func (hm *HardwareManager) checkADBAvailability() bool {
	cmd := exec.Command("adb", "version")
	return cmd.Run() == nil
}

// getConnectedDevice gets the first connected ADB device
func (hm *HardwareManager) getConnectedDevice() string {
	cmd := exec.Command("adb", "devices")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "\tdevice") {
			return strings.Fields(line)[0]
		}
	}

	return ""
}

// GetDeviceInfo retrieves comprehensive Android device information
func (hm *HardwareManager) GetDeviceInfo() (*AndroidDevice, error) {
	device := &AndroidDevice{
		Capabilities: make(map[string]bool),
		Sensors:      make([]AndroidSensor, 0),
	}

	if hm.isAndroid {
		return hm.getDeviceInfoNative(device)
	} else if hm.adbEnabled && hm.deviceID != "" {
		return hm.getDeviceInfoADB(device)
	}

	return nil, fmt.Errorf("no Android device access available")
}

// getDeviceInfoNative gets device info when running natively on Android
func (hm *HardwareManager) getDeviceInfoNative(device *AndroidDevice) (*AndroidDevice, error) {
	// Get basic device properties
	if model, err := hm.getProperty("ro.product.model"); err == nil {
		device.Model = model
	}

	if manufacturer, err := hm.getProperty("ro.product.manufacturer"); err == nil {
		device.Manufacturer = manufacturer
	}

	if version, err := hm.getProperty("ro.build.version.release"); err == nil {
		device.AndroidVersion = version
	}

	if build, err := hm.getProperty("ro.build.display.id"); err == nil {
		device.BuildNumber = build
	}

	// Get sensor information
	sensors, err := hm.getSensorsNative()
	if err == nil {
		device.Sensors = sensors
	}

	// Get network capabilities
	device.NetworkInfo = hm.getNetworkInfoNative()

	return device, nil
}

// getDeviceInfoADB gets device info via ADB
func (hm *HardwareManager) getDeviceInfoADB(device *AndroidDevice) (*AndroidDevice, error) {
	device.ID = hm.deviceID

	// Get device properties via ADB
	props := map[string]*string{
		"ro.product.model":        &device.Model,
		"ro.product.manufacturer": &device.Manufacturer,
		"ro.build.version.release": &device.AndroidVersion,
		"ro.build.display.id":     &device.BuildNumber,
	}

	for prop, field := range props {
		if value, err := hm.getPropertyADB(prop); err == nil {
			*field = value
		}
	}

	// Get capabilities
	device.Capabilities["wifi"] = hm.hasWiFiCapability()
	device.Capabilities["bluetooth"] = hm.hasBluetoothCapability()
	device.Capabilities["nfc"] = hm.hasNFCCapability()
	device.Capabilities["cellular"] = hm.hasCellularCapability()
	device.Capabilities["gps"] = hm.hasGPSCapability()

	// Get sensor information
	sensors, err := hm.getSensorsADB()
	if err == nil {
		device.Sensors = sensors
	}

	// Get network information
	device.NetworkInfo = hm.getNetworkInfoADB()

	return device, nil
}

// getProperty gets an Android system property natively
func (hm *HardwareManager) getProperty(prop string) (string, error) {
	cmd := exec.Command("getprop", prop)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// getPropertyADB gets an Android system property via ADB
func (hm *HardwareManager) getPropertyADB(prop string) (string, error) {
	cmd := exec.Command("adb", "-s", hm.deviceID, "shell", "getprop", prop)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// getSensorsNative gets sensor information natively
func (hm *HardwareManager) getSensorsNative() ([]AndroidSensor, error) {
	// This would require Android-specific APIs or native code
	// For now, return basic sensor list
	return []AndroidSensor{
		{Name: "Accelerometer", Type: "accelerometer", Available: true},
		{Name: "Gyroscope", Type: "gyroscope", Available: true},
		{Name: "Magnetometer", Type: "magnetometer", Available: true},
		{Name: "GPS", Type: "gps", Available: true},
		{Name: "Proximity", Type: "proximity", Available: true},
		{Name: "Light", Type: "light", Available: true},
	}, nil
}

// getSensorsADB gets sensor information via ADB
func (hm *HardwareManager) getSensorsADB() ([]AndroidSensor, error) {
	// Use dumpsys to get sensor information
	cmd := exec.Command("adb", "-s", hm.deviceID, "shell", "dumpsys", "sensorservice")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return hm.parseSensorOutput(string(output)), nil
}

// parseSensorOutput parses sensor information from dumpsys output
func (hm *HardwareManager) parseSensorOutput(output string) []AndroidSensor {
	sensors := make([]AndroidSensor, 0)
	lines := strings.Split(output, "\n")

	var currentSensor *AndroidSensor

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Look for sensor entries
		if strings.Contains(line, " | ") && (strings.Contains(line, "Accelerometer") || 
			strings.Contains(line, "Gyroscope") || strings.Contains(line, "Magnetometer") ||
			strings.Contains(line, "Proximity") || strings.Contains(line, "Light")) {
			
			if currentSensor != nil {
				sensors = append(sensors, *currentSensor)
			}

			currentSensor = &AndroidSensor{
				Available: true,
			}

			// Parse sensor name and type
			if strings.Contains(line, "Accelerometer") {
				currentSensor.Name = "Accelerometer"
				currentSensor.Type = "accelerometer"
			} else if strings.Contains(line, "Gyroscope") {
				currentSensor.Name = "Gyroscope"
				currentSensor.Type = "gyroscope"
			} else if strings.Contains(line, "Magnetometer") {
				currentSensor.Name = "Magnetometer"
				currentSensor.Type = "magnetometer"
			}
		}

		// Parse vendor information
		if currentSensor != nil && strings.Contains(line, "vendor:") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				currentSensor.Vendor = strings.TrimSpace(parts[1])
			}
		}
	}

	if currentSensor != nil {
		sensors = append(sensors, *currentSensor)
	}

	return sensors
}

// Network capability checks
func (hm *HardwareManager) hasWiFiCapability() bool {
	cmd := exec.Command("adb", "-s", hm.deviceID, "shell", "dumpsys", "wifi")
	return cmd.Run() == nil
}

func (hm *HardwareManager) hasBluetoothCapability() bool {
	cmd := exec.Command("adb", "-s", hm.deviceID, "shell", "dumpsys", "bluetooth_manager")
	return cmd.Run() == nil
}

func (hm *HardwareManager) hasNFCCapability() bool {
	cmd := exec.Command("adb", "-s", hm.deviceID, "shell", "dumpsys", "nfc")
	return cmd.Run() == nil
}

func (hm *HardwareManager) hasCellularCapability() bool {
	cmd := exec.Command("adb", "-s", hm.deviceID, "shell", "dumpsys", "telephony.registry")
	return cmd.Run() == nil
}

func (hm *HardwareManager) hasGPSCapability() bool {
	cmd := exec.Command("adb", "-s", hm.deviceID, "shell", "dumpsys", "location")
	return cmd.Run() == nil
}

// getNetworkInfoNative gets network information natively
func (hm *HardwareManager) getNetworkInfoNative() *AndroidNetworkInfo {
	info := &AndroidNetworkInfo{}

	// This would use Android APIs to get network status
	// For now, return basic information
	info.WiFiEnabled = true
	info.BluetoothEnabled = true
	info.NFCEnabled = true
	info.CellularEnabled = true

	return info
}

// getNetworkInfoADB gets network information via ADB
func (hm *HardwareManager) getNetworkInfoADB() *AndroidNetworkInfo {
	info := &AndroidNetworkInfo{}

	// WiFi information
	if output, err := hm.runADBCommand("dumpsys", "wifi"); err == nil {
		info.WiFiEnabled = strings.Contains(output, "Wi-Fi is enabled")
		if ssid := hm.extractWiFiSSID(output); ssid != "" {
			info.ConnectedSSID = ssid
		}
	}

	// Bluetooth information
	if output, err := hm.runADBCommand("dumpsys", "bluetooth_manager"); err == nil {
		info.BluetoothEnabled = strings.Contains(output, "enabled: true")
		if mac := hm.extractBluetoothMAC(output); mac != "" {
			info.BluetoothMAC = mac
		}
	}

	// NFC information
	if output, err := hm.runADBCommand("dumpsys", "nfc"); err == nil {
		info.NFCEnabled = strings.Contains(output, "NFC Enabled: true")
	}

	// Cellular information
	if output, err := hm.runADBCommand("dumpsys", "telephony.registry"); err == nil {
		if operator := hm.extractMobileOperator(output); operator != "" {
			info.MobileOperator = operator
		}
		info.SignalStrength = hm.extractSignalStrength(output)
	}

	return info
}

// runADBCommand executes an ADB command and returns output
func (hm *HardwareManager) runADBCommand(args ...string) (string, error) {
	fullArgs := append([]string{"-s", hm.deviceID, "shell"}, args...)
	cmd := exec.Command("adb", fullArgs...)
	output, err := cmd.Output()
	return string(output), err
}

// extractWiFiSSID extracts connected WiFi SSID from dumpsys output
func (hm *HardwareManager) extractWiFiSSID(output string) string {
	re := regexp.MustCompile(`SSID: "([^"]+)"`)
	if matches := re.FindStringSubmatch(output); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractBluetoothMAC extracts Bluetooth MAC address
func (hm *HardwareManager) extractBluetoothMAC(output string) string {
	re := regexp.MustCompile(`Address: ([0-9A-Fa-f:]{17})`)
	if matches := re.FindStringSubmatch(output); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractMobileOperator extracts mobile network operator
func (hm *HardwareManager) extractMobileOperator(output string) string {
	re := regexp.MustCompile(`OperatorAlphaLong=([^\s]+)`)
	if matches := re.FindStringSubmatch(output); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// extractSignalStrength extracts cellular signal strength
func (hm *HardwareManager) extractSignalStrength(output string) int {
	re := regexp.MustCompile(`SignalStrength: (-?\d+)`)
	if matches := re.FindStringSubmatch(output); len(matches) > 1 {
		if strength, err := strconv.Atoi(matches[1]); err == nil {
			return strength
		}
	}
	return 0
}

// StartHardwareMonitoring starts continuous hardware monitoring
func (hm *HardwareManager) StartHardwareMonitoring(ctx context.Context) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := hm.monitorHardwareChanges(); err != nil {
				fmt.Printf("Hardware monitoring error: %v\n", err)
			}
		}
	}
}

// monitorHardwareChanges checks for hardware state changes
func (hm *HardwareManager) monitorHardwareChanges() error {
	// Monitor network state changes
	if hm.adbEnabled && hm.deviceID != "" {
		networkInfo := hm.getNetworkInfoADB()
		// Log or alert on significant changes
		fmt.Printf("Network monitoring: WiFi=%v, BT=%v, NFC=%v\n", 
			networkInfo.WiFiEnabled, networkInfo.BluetoothEnabled, networkInfo.NFCEnabled)
	}

	return nil
}

// RequestPermissions requests necessary Android permissions
func (hm *HardwareManager) RequestPermissions() error {
	if !hm.adbEnabled || hm.deviceID == "" {
		return fmt.Errorf("ADB not available")
	}

	// List of permissions needed for surveillance detection
	permissions := []string{
		"android.permission.ACCESS_WIFI_STATE",
		"android.permission.ACCESS_NETWORK_STATE",
		"android.permission.BLUETOOTH",
		"android.permission.BLUETOOTH_ADMIN",
		"android.permission.NFC",
		"android.permission.ACCESS_COARSE_LOCATION",
		"android.permission.ACCESS_FINE_LOCATION",
		"android.permission.READ_PHONE_STATE",
	}

	for _, permission := range permissions {
		// Check if permission is already granted
		cmd := exec.Command("adb", "-s", hm.deviceID, "shell", "pm", "list", "permissions", "-g")
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), permission) {
			hm.permissions[permission] = true
		}
	}

	return nil
}

// IsAvailable checks if Android hardware access is available
func (hm *HardwareManager) IsAvailable() bool {
	return hm.isAndroid || (hm.adbEnabled && hm.deviceID != "")
}

// GetCapabilities returns available hardware capabilities
func (hm *HardwareManager) GetCapabilities() map[string]bool {
	capabilities := map[string]bool{
		"native_android": hm.isAndroid,
		"adb_available":  hm.adbEnabled,
		"device_connected": hm.deviceID != "",
	}

	if hm.isAndroid || (hm.adbEnabled && hm.deviceID != "") {
		capabilities["wifi_scanning"] = true
		capabilities["bluetooth_scanning"] = true
		capabilities["nfc_scanning"] = true
		capabilities["cellular_info"] = true
		capabilities["sensor_access"] = true
	}

	return capabilities
}
