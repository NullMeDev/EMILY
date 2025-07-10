package android

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/database"
	"github.com/null/emily/internal/intelligence"
	"github.com/null/emily/internal/models"
	"github.com/null/emily/internal/scanner"
)

// AndroidService manages background surveillance detection on Android
type AndroidService struct {
	config           *config.Config
	db              *database.Database
	hardwareManager *HardwareManager
	scannerManager  *scanner.Manager
	intelligence    *intelligence.IntelligenceEngine
	
	// Service state
	running          bool
	serviceContext   context.Context
	serviceCancel    context.CancelFunc
	
	// Android-specific
	foregroundService bool
	notificationID    int
	lastNotification  time.Time
	
	// Performance monitoring
	scanCount        int64
	lastScanDuration time.Duration
	batteryOptimized bool
}

// ServiceConfig represents Android service configuration
type ServiceConfig struct {
	ScanInterval       time.Duration `json:"scan_interval"`
	BackgroundMode     bool          `json:"background_mode"`
	PersistentMode     bool          `json:"persistent_mode"`
	BatteryOptimized   bool          `json:"battery_optimized"`
	NotificationMode   string        `json:"notification_mode"` // silent, discrete, full
	AutoStart          bool          `json:"auto_start"`
	StealthMode        bool          `json:"stealth_mode"`
	WakeLockEnabled    bool          `json:"wake_lock_enabled"`
}

// ServiceStatus represents current service status
type ServiceStatus struct {
	Running           bool          `json:"running"`
	Uptime           time.Duration `json:"uptime"`
	ScansPerformed   int64         `json:"scans_performed"`
	ThreatsDetected  int           `json:"threats_detected"`
	LastScanTime     time.Time     `json:"last_scan_time"`
	LastScanDuration time.Duration `json:"last_scan_duration"`
	BatteryUsage     float64       `json:"battery_usage"`
	MemoryUsage      int64         `json:"memory_usage"`
}

// ThreatAlert represents an alert for detected threats
type ThreatAlert struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	ThreatType  string                 `json:"threat_type"`
	ThreatLevel int                    `json:"threat_level"`
	DeviceInfo  map[string]interface{} `json:"device_info"`
	Location    *LocationInfo          `json:"location,omitempty"`
	Actions     []string               `json:"actions"`
	Dismissed   bool                   `json:"dismissed"`
}

// LocationInfo represents location context for threats
type LocationInfo struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Accuracy  float64 `json:"accuracy"`
	Address   string  `json:"address,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// NewAndroidService creates a new Android service
func NewAndroidService(cfg *config.Config, db *database.Database) (*AndroidService, error) {
	hardwareManager, err := NewHardwareManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create hardware manager: %w", err)
	}

	scannerManager, err := scanner.NewManager(cfg, db)
	if err != nil {
		return nil, fmt.Errorf("failed to create scanner manager: %w", err)
	}

	intelligenceEngine, err := intelligence.NewIntelligenceEngine(cfg, db)
	if err != nil {
		return nil, fmt.Errorf("failed to create intelligence engine: %w", err)
	}

	service := &AndroidService{
		config:           cfg,
		db:              db,
		hardwareManager: hardwareManager,
		scannerManager:  scannerManager,
		intelligence:    intelligenceEngine,
		notificationID:  12345, // Unique notification ID
		batteryOptimized: true,
	}

	return service, nil
}

// Start starts the Android background service
func (as *AndroidService) Start() error {
	if as.running {
		return fmt.Errorf("service already running")
	}

	// Create service context
	as.serviceContext, as.serviceCancel = context.WithCancel(context.Background())

	// Check if we need to start as foreground service
	if as.shouldRunAsForegroundService() {
		if err := as.startForegroundService(); err != nil {
			return fmt.Errorf("failed to start foreground service: %w", err)
		}
	}

	// Request necessary permissions
	if err := as.requestPermissions(); err != nil {
		fmt.Printf("Warning: Some permissions not granted: %v\n", err)
	}

	// Initialize hardware monitoring
	go as.startHardwareMonitoring()

	// Start main service loop
	go as.serviceLoop()

	// Start continuous intelligence analysis
	go as.intelligence.ProcessContinuousAnalysis(as.serviceContext)

	as.running = true
	fmt.Println("Android surveillance detection service started")

	return nil
}

// Stop stops the Android service
func (as *AndroidService) Stop() error {
	if !as.running {
		return fmt.Errorf("service not running")
	}

	// Cancel service context
	if as.serviceCancel != nil {
		as.serviceCancel()
	}

	// Stop foreground service if running
	if as.foregroundService {
		as.stopForegroundService()
	}

	as.running = false
	fmt.Println("Android surveillance detection service stopped")

	return nil
}

// shouldRunAsForegroundService determines if foreground service is needed
func (as *AndroidService) shouldRunAsForegroundService() bool {
	// Always use foreground service for continuous monitoring
	// This prevents Android from killing the service
	return true
}

// startForegroundService starts Android foreground service
func (as *AndroidService) startForegroundService() error {
	if !as.hardwareManager.adbEnabled {
		// Can't control Android notifications without ADB or native integration
		// In a real implementation, this would use Android APIs
		fmt.Println("Foreground service simulation: Creating persistent notification")
		as.foregroundService = true
		return nil
	}

	// Create notification channel
	if err := as.createNotificationChannel(); err != nil {
		return fmt.Errorf("failed to create notification channel: %w", err)
	}

	// Start foreground service with notification
	if err := as.showPersistentNotification(); err != nil {
		return fmt.Errorf("failed to show persistent notification: %w", err)
	}

	as.foregroundService = true
	return nil
}

// stopForegroundService stops the foreground service
func (as *AndroidService) stopForegroundService() {
	if as.hardwareManager.adbEnabled {
		// Cancel persistent notification
		cmd := exec.Command("adb", "-s", as.hardwareManager.deviceID, "shell", 
			"cmd", "notification", "cancel", strconv.Itoa(as.notificationID))
		cmd.Run()
	}

	as.foregroundService = false
}

// createNotificationChannel creates Android notification channel
func (as *AndroidService) createNotificationChannel() error {
	if !as.hardwareManager.adbEnabled {
		return nil
	}

	// Create notification channel for Android 8.0+
	channelCmd := []string{
		"adb", "-s", as.hardwareManager.deviceID, "shell",
		"cmd", "notification", "create_channel",
		"emily_surveillance", "EMILY Surveillance Detection",
		"IMPORTANCE_LOW", // Low importance to avoid interrupting user
	}

	cmd := exec.Command(channelCmd[0], channelCmd[1:]...)
	return cmd.Run()
}

// showPersistentNotification shows a persistent notification
func (as *AndroidService) showPersistentNotification() error {
	if !as.hardwareManager.adbEnabled {
		return nil
	}

	// Show persistent notification
	notificationCmd := []string{
		"adb", "-s", as.hardwareManager.deviceID, "shell",
		"cmd", "notification", "post",
		"-S", "bigtext",
		"-t", "EMILY Surveillance Detection",
		"-c", "emily_surveillance",
		strconv.Itoa(as.notificationID),
		"Monitoring for surveillance devices...",
	}

	cmd := exec.Command(notificationCmd[0], notificationCmd[1:]...)
	return cmd.Run()
}

// requestPermissions requests necessary Android permissions
func (as *AndroidService) requestPermissions() error {
	return as.hardwareManager.RequestPermissions()
}

// startHardwareMonitoring starts hardware monitoring
func (as *AndroidService) startHardwareMonitoring() {
	as.hardwareManager.StartHardwareMonitoring(as.serviceContext)
}

// serviceLoop is the main service loop
func (as *AndroidService) serviceLoop() {
	scanInterval := as.config.Core.ScanInterval
	if scanInterval == 0 {
		scanInterval = 30 * time.Second // Default interval
	}

	// Adjust interval based on battery optimization
	if as.batteryOptimized {
		scanInterval *= 2 // Double interval to save battery
	}

	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-as.serviceContext.Done():
			return
		case <-ticker.C:
			as.performScan()
		}
	}
}

// performScan performs a surveillance detection scan
func (as *AndroidService) performScan() {
	startTime := time.Now()
	as.scanCount++

	// Perform scan based on available hardware
	devices, err := as.scannerManager.ScanAll(as.serviceContext, 10*time.Second)
	if err != nil {
		fmt.Printf("Scan error: %v\n", err)
		return
	}

	// Analyze detected devices
	threats := make([]*ThreatAlert, 0)
	for _, device := range devices {
		// Perform threat analysis
		analysis, err := as.intelligence.AnalyzeDevice(&device)
		if err != nil {
			continue
		}

		// Create threat alert if significant threat detected
		if analysis.ThreatLevel >= as.config.Notifications.Alerts.ThreatLevel {
			alert := as.createThreatAlert(&device, analysis)
			threats = append(threats, alert)
		}
	}

	// Process threat alerts
	for _, alert := range threats {
		as.processThreatAlert(alert)
	}

	// Update performance metrics
	as.lastScanDuration = time.Since(startTime)

	// Update persistent notification with scan results
	if as.foregroundService && time.Since(as.lastNotification) > time.Minute {
		as.updatePersistentNotification(len(devices), len(threats))
		as.lastNotification = time.Now()
	}
}

// createThreatAlert creates a threat alert from analysis results
func (as *AndroidService) createThreatAlert(device *models.Device, analysis *intelligence.ThreatAnalysisResult) *ThreatAlert {
	alert := &ThreatAlert{
		ID:          fmt.Sprintf("alert_%d_%s", time.Now().Unix(), device.ID),
		Timestamp:   time.Now(),
		ThreatType:  strings.Join(analysis.ThreatTypes, ","),
		ThreatLevel: analysis.ThreatLevel,
		DeviceInfo: map[string]interface{}{
			"id":           device.ID,
			"name":         device.Name,
			"type":         device.Type,
			"mac":          device.MAC,
			"manufacturer": device.Manufacturer,
			"signal_level": device.SignalLevel,
		},
		Actions:   analysis.Recommendations,
		Dismissed: false,
	}

	// Add location if available
	if location := as.getCurrentLocation(); location != nil {
		alert.Location = location
	}

	return alert
}

// processThreatAlert processes and responds to a threat alert
func (as *AndroidService) processThreatAlert(alert *ThreatAlert) {
	// Log the threat
	fmt.Printf("THREAT DETECTED: %s (Level: %d) at %s\n", 
		alert.ThreatType, alert.ThreatLevel, alert.Timestamp.Format(time.RFC3339))

	// Save to database
	as.saveThreatAlert(alert)

	// Send notification based on threat level
	if alert.ThreatLevel >= 7 {
		as.showHighPriorityAlert(alert)
	} else if alert.ThreatLevel >= 5 {
		as.showMediumPriorityAlert(alert)
	}

	// Execute automated responses if configured
	as.executeAutomatedResponse(alert)
}

// showHighPriorityAlert shows a high priority threat alert
func (as *AndroidService) showHighPriorityAlert(alert *ThreatAlert) {
	if !as.hardwareManager.adbEnabled {
		fmt.Printf("HIGH PRIORITY ALERT: %s\n", alert.ThreatType)
		return
	}

	// Show urgent notification
	alertCmd := []string{
		"adb", "-s", as.hardwareManager.deviceID, "shell",
		"cmd", "notification", "post",
		"-S", "bigtext", "-p", "high",
		"-t", "🚨 SURVEILLANCE DETECTED",
		"-c", "emily_surveillance",
		strconv.Itoa(as.notificationID + 1),
		fmt.Sprintf("High threat: %s detected nearby", alert.ThreatType),
	}

	cmd := exec.Command(alertCmd[0], alertCmd[1:]...)
	cmd.Run()
}

// showMediumPriorityAlert shows a medium priority threat alert
func (as *AndroidService) showMediumPriorityAlert(alert *ThreatAlert) {
	if !as.hardwareManager.adbEnabled {
		fmt.Printf("MEDIUM PRIORITY ALERT: %s\n", alert.ThreatType)
		return
	}

	// Show normal notification
	alertCmd := []string{
		"adb", "-s", as.hardwareManager.deviceID, "shell",
		"cmd", "notification", "post",
		"-S", "bigtext",
		"-t", "⚠️ Potential Threat",
		"-c", "emily_surveillance",
		strconv.Itoa(as.notificationID + 2),
		fmt.Sprintf("Potential %s detected", alert.ThreatType),
	}

	cmd := exec.Command(alertCmd[0], alertCmd[1:]...)
	cmd.Run()
}

// executeAutomatedResponse executes automated responses to threats
func (as *AndroidService) executeAutomatedResponse(alert *ThreatAlert) {
	// Example automated responses (would be configurable)
	switch alert.ThreatLevel {
	case 9, 10:
		// Critical threat - consider aggressive countermeasures
		fmt.Println("CRITICAL THREAT: Consider immediate evasive action")
	case 7, 8:
		// High threat - enable countermeasures
		fmt.Println("HIGH THREAT: Enabling enhanced monitoring")
	case 5, 6:
		// Medium threat - increase monitoring
		fmt.Println("MEDIUM THREAT: Increasing scan frequency")
	}
}

// updatePersistentNotification updates the persistent notification
func (as *AndroidService) updatePersistentNotification(deviceCount, threatCount int) {
	if !as.hardwareManager.adbEnabled {
		return
	}

	status := fmt.Sprintf("Scanned %d devices, %d threats detected", deviceCount, threatCount)
	
	notificationCmd := []string{
		"adb", "-s", as.hardwareManager.deviceID, "shell",
		"cmd", "notification", "post",
		"-S", "bigtext",
		"-t", "EMILY Surveillance Detection",
		"-c", "emily_surveillance",
		strconv.Itoa(as.notificationID),
		status,
	}

	cmd := exec.Command(notificationCmd[0], notificationCmd[1:]...)
	cmd.Run()
}

// getCurrentLocation gets current location (stub implementation)
func (as *AndroidService) getCurrentLocation() *LocationInfo {
	// In a real implementation, this would use Android location services
	// For now, return nil to indicate no location available
	return nil
}

// saveThreatAlert saves threat alert to database
func (as *AndroidService) saveThreatAlert(alert *ThreatAlert) {
	// Convert alert to JSON and store
	alertData, err := json.Marshal(alert)
	if err != nil {
		fmt.Printf("Failed to serialize alert: %v\n", err)
		return
	}

	// Save to alerts table or file
	alertsDir := filepath.Join(as.config.Data.StoragePath, "alerts")
	os.MkdirAll(alertsDir, 0755)
	
	alertFile := filepath.Join(alertsDir, fmt.Sprintf("%s.json", alert.ID))
	if err := os.WriteFile(alertFile, alertData, 0644); err != nil {
		fmt.Printf("Failed to save alert: %v\n", err)
	}
}

// GetStatus returns current service status
func (as *AndroidService) GetStatus() *ServiceStatus {
	var uptime time.Duration
	if as.running && as.serviceContext != nil {
		// Calculate uptime (simplified)
		uptime = time.Since(time.Now().Add(-time.Hour)) // Placeholder
	}

	return &ServiceStatus{
		Running:          as.running,
		Uptime:          uptime,
		ScansPerformed:  as.scanCount,
		ThreatsDetected: as.getThreatCount(),
		LastScanDuration: as.lastScanDuration,
		BatteryUsage:    as.getBatteryUsage(),
		MemoryUsage:     as.getMemoryUsage(),
	}
}

// getThreatCount gets total threat count
func (as *AndroidService) getThreatCount() int {
	// Count threat alert files
	alertsDir := filepath.Join(as.config.Data.StoragePath, "alerts")
	files, err := filepath.Glob(filepath.Join(alertsDir, "*.json"))
	if err != nil {
		return 0
	}
	return len(files)
}

// getBatteryUsage gets estimated battery usage
func (as *AndroidService) getBatteryUsage() float64 {
	// Simplified battery usage estimation
	// In a real implementation, this would query Android battery stats
	return float64(as.scanCount) * 0.01 // 1% per 100 scans
}

// getMemoryUsage gets current memory usage
func (as *AndroidService) getMemoryUsage() int64 {
	// Simplified memory usage
	return int64(as.scanCount * 1024) // Rough estimate
}

// IsRunning returns whether the service is running
func (as *AndroidService) IsRunning() bool {
	return as.running
}

// GetHardwareCapabilities returns available hardware capabilities
func (as *AndroidService) GetHardwareCapabilities() map[string]bool {
	return as.hardwareManager.GetCapabilities()
}

// SetBatteryOptimization sets battery optimization mode
func (as *AndroidService) SetBatteryOptimization(enabled bool) {
	as.batteryOptimized = enabled
	fmt.Printf("Battery optimization %s\n", map[bool]string{true: "enabled", false: "disabled"}[enabled])
}
