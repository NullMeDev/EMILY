package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/database"
	"github.com/null/emily/internal/models"
	"github.com/sirupsen/logrus"
)

// WiresharkEngine handles packet capture and analysis
type WiresharkEngine struct {
	isRunning bool
	logger    *logrus.Logger
}

// HiddenNetworkScanner detects hidden networks and devices
type HiddenNetworkScanner struct {
	isRunning bool
	logger    *logrus.Logger
}

// Scanner represents the main signal detection engine
type Scanner struct {
	config   *config.Config
	db       *database.Database
	wifi     WiFiScanner
	bluetooth BluetoothScanner
	cellular CellularScanner
	nfc      NFCScanner
	
	// Advanced scanning capabilities
	signumScanner    *SignumScanner
	intrusionScanner *IntrusionScanner
	passwordCracker  *PasswordCracker
	wiresharkEngine  *WiresharkEngine
	hiddenNetScanner *HiddenNetworkScanner
	
	// State management
	isRunning bool
	sessions  map[string]*models.ScanSession
	mutex     sync.RWMutex
	
	// 24/7 Monitoring state
	autonomousMode   bool
	lastScanResults  map[string]*models.Device
	baselineNetworks map[string]*models.NetworkBaseline
	intrusionAlerts  chan *models.IntrusionAlert
	passwordAttempts chan *models.PasswordAttempt
	
	// Notification channels
	deviceChan chan *models.Device
	alertChan  chan *models.Alert
	statsChan  chan *models.Statistics
	
	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc
}

// ScannerInterface defines the interface for individual signal scanners
type ScannerInterface interface {
	Start(ctx context.Context) error
	Stop() error
	Scan(ctx context.Context, duration time.Duration) ([]models.Device, error)
	IsAvailable() bool
	GetType() string
}

// WiFiScanner interface for Wi-Fi detection
type WiFiScanner interface {
	ScannerInterface
	ScanChannels(ctx context.Context, channels []int, duration time.Duration) ([]models.WiFiDevice, error)
	GetAvailableChannels() []int
}

// BluetoothScanner interface for Bluetooth detection
type BluetoothScanner interface {
	ScannerInterface
	ScanLE(ctx context.Context, duration time.Duration) ([]models.BluetoothDevice, error)
	ScanClassic(ctx context.Context, duration time.Duration) ([]models.BluetoothDevice, error)
}

// CellularScanner interface for cellular detection
type CellularScanner interface {
	ScannerInterface
	GetCellInfo() (*models.CellularDevice, error)
	DetectIMSICatcher() (bool, error)
}

// NFCScanner interface for NFC detection
type NFCScanner interface {
	ScannerInterface
	ScanTags(ctx context.Context, duration time.Duration) ([]models.NFCDevice, error)
	IsNFCEnabled() bool
}

// New creates a new scanner instance
func New(cfg *config.Config, db *database.Database) (*Scanner, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	scanner := &Scanner{
		config:    cfg,
		db:        db,
		sessions:  make(map[string]*models.ScanSession),
		deviceChan: make(chan *models.Device, 100),
		alertChan:  make(chan *models.Alert, 50),
		statsChan:  make(chan *models.Statistics, 10),
		ctx:       ctx,
		cancel:    cancel,
	}
	
	// Initialize platform-specific scanners
	if err := scanner.initScanners(); err != nil {
		return nil, fmt.Errorf("failed to initialize scanners: %w", err)
	}
	
	return scanner, nil
}

// initScanners initializes the platform-specific scanners
func (s *Scanner) initScanners() error {
	// Initialize Wi-Fi scanner
	if s.config.Detection.WiFi.Enabled {
		wifi, err := NewWiFiScanner(s.config)
		if err != nil {
			return fmt.Errorf("failed to initialize Wi-Fi scanner: %w", err)
		}
		s.wifi = wifi
	}
	
	// Initialize Bluetooth scanner
	if s.config.Detection.Bluetooth.Enabled {
		bluetooth, err := NewBluetoothScanner(s.config)
		if err != nil {
			return fmt.Errorf("failed to initialize Bluetooth scanner: %w", err)
		}
		s.bluetooth = bluetooth
	}
	
	// Initialize Cellular scanner
	if s.config.Detection.Cellular.Enabled {
		cellular, err := NewCellularScanner(s.config)
		if err != nil {
			return fmt.Errorf("failed to initialize Cellular scanner: %w", err)
		}
		s.cellular = cellular
	}
	
	// Initialize NFC scanner
	if s.config.Detection.NFC.Enabled {
		nfc, err := NewNFCScanner(s.config)
		if err != nil {
			return fmt.Errorf("failed to initialize NFC scanner: %w", err)
		}
		s.nfc = nfc
	}
	
	return nil
}

// Start starts the scanner engine
func (s *Scanner) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	if s.isRunning {
		return fmt.Errorf("scanner is already running")
	}
	
	// Start individual scanners
	if s.wifi != nil && s.wifi.IsAvailable() {
		if err := s.wifi.Start(s.ctx); err != nil {
			return fmt.Errorf("failed to start Wi-Fi scanner: %w", err)
		}
	}
	
	if s.bluetooth != nil && s.bluetooth.IsAvailable() {
		if err := s.bluetooth.Start(s.ctx); err != nil {
			return fmt.Errorf("failed to start Bluetooth scanner: %w", err)
		}
	}
	
	if s.cellular != nil && s.cellular.IsAvailable() {
		if err := s.cellular.Start(s.ctx); err != nil {
			return fmt.Errorf("failed to start Cellular scanner: %w", err)
		}
	}
	
	if s.nfc != nil && s.nfc.IsAvailable() {
		if err := s.nfc.Start(s.ctx); err != nil {
			return fmt.Errorf("failed to start NFC scanner: %w", err)
		}
	}
	
	s.isRunning = true
	
	// Start background processing goroutines
	go s.processDevices()
	go s.processAlerts()
	go s.processStatistics()
	go s.continuousScanning()
	
	return nil
}

// Stop stops the scanner engine
func (s *Scanner) Stop() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	if !s.isRunning {
		return nil
	}
	
	// Cancel context to stop all operations
	s.cancel()
	
	// Stop individual scanners
	if s.wifi != nil {
		s.wifi.Stop()
	}
	if s.bluetooth != nil {
		s.bluetooth.Stop()
	}
	if s.cellular != nil {
		s.cellular.Stop()
	}
	if s.nfc != nil {
		s.nfc.Stop()
	}
	
	s.isRunning = false
	
	return nil
}

// Scan performs a single scan operation
func (s *Scanner) Scan(scanType string, duration time.Duration) (*models.ScanResult, error) {
	sessionID := s.generateSessionID()
	session := &models.ScanSession{
		ID:        sessionID,
		StartTime: time.Now(),
		ScanType:  scanType,
		CreatedAt: time.Now(),
	}
	
	s.mutex.Lock()
	s.sessions[sessionID] = session
	s.mutex.Unlock()
	
	defer func() {
		s.mutex.Lock()
		delete(s.sessions, sessionID)
		s.mutex.Unlock()
	}()
	
	result := &models.ScanResult{
		SessionID:       sessionID,
		DevicesFound:    make([]models.Device, 0),
		ThreatsFound:    make([]models.ThreatAssessment, 0),
		AlertsGenerated: make([]models.Alert, 0),
		Statistics:      make(map[string]interface{}),
	}
	
	startTime := time.Now()
	
	// Perform scans based on enabled detectors
	var wg sync.WaitGroup
	var mutex sync.Mutex
	
	// Wi-Fi scan
	if s.wifi != nil && s.wifi.IsAvailable() && s.config.Detection.WiFi.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			devices, err := s.wifi.Scan(s.ctx, duration)
			if err != nil {
				result.Error = fmt.Sprintf("WiFi scan error: %v", err)
				return
			}
			
				mutex.Lock()
				for _, device := range devices {
					result.DevicesFound = append(result.DevicesFound, device)
					s.processDevice(&device)
				}
				mutex.Unlock()
		}()
	}
	
	// Bluetooth scan
	if s.bluetooth != nil && s.bluetooth.IsAvailable() && s.config.Detection.Bluetooth.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			devices, err := s.bluetooth.Scan(s.ctx, duration)
			if err != nil {
				result.Error = fmt.Sprintf("Bluetooth scan error: %v", err)
				return
			}
			
				mutex.Lock()
				for _, device := range devices {
					result.DevicesFound = append(result.DevicesFound, device)
					s.processDevice(&device)
				}
				mutex.Unlock()
		}()
	}
	
	// Cellular scan
	if s.cellular != nil && s.cellular.IsAvailable() && s.config.Detection.Cellular.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			devices, err := s.cellular.Scan(s.ctx, duration)
			if err != nil {
				result.Error = fmt.Sprintf("Cellular scan error: %v", err)
				return
			}
			
				mutex.Lock()
				for _, device := range devices {
					result.DevicesFound = append(result.DevicesFound, device)
					s.processDevice(&device)
				}
				mutex.Unlock()
		}()
	}
	
	// NFC scan
	if s.nfc != nil && s.nfc.IsAvailable() && s.config.Detection.NFC.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			devices, err := s.nfc.Scan(s.ctx, duration)
			if err != nil {
				result.Error = fmt.Sprintf("NFC scan error: %v", err)
				return
			}
			
				mutex.Lock()
				for _, device := range devices {
					result.DevicesFound = append(result.DevicesFound, device)
					s.processDevice(&device)
				}
				mutex.Unlock()
		}()
	}
	
	// Wait for all scans to complete
	wg.Wait()
	
	result.Duration = time.Since(startTime)
	
	// Update session
	endTime := time.Now()
	session.EndTime = &endTime
	session.Duration = int(result.Duration.Seconds())
	session.DevicesFound = len(result.DevicesFound)
	
	// Save session to database
	if err := s.db.SaveScanSession(session); err != nil {
		fmt.Printf("Error saving scan session: %v\n", err)
	}
	
	return result, nil
}

// processDevice processes a detected device
func (s *Scanner) processDevice(device *models.Device) {
	// Check if device is whitelisted
	whitelisted, err := s.db.IsWhitelisted(device.Type, device.MAC)
	if err == nil {
		device.IsWhitelisted = whitelisted
	}
	
	// Perform threat assessment
	s.assessThreat(device)
	
	// Save device to database
	if err := s.db.SaveDevice(device); err != nil {
		fmt.Printf("Error saving device: %v\n", err)
	}
	
	// Send to device channel for real-time processing
	select {
	case s.deviceChan <- device:
	default:
		// Channel is full, skip
	}
}

// assessThreat performs threat assessment on a device
func (s *Scanner) assessThreat(device *models.Device) {
	threatLevel := 0
	indicators := make([]string, 0)
	
	// Basic threat indicators
	if device.IsTransient() && device.SignalLevel > -40 {
		threatLevel += 2
		indicators = append(indicators, "Strong signal from transient device")
	}
	
	if !device.IsWhitelisted && device.SignalLevel > -30 {
		threatLevel += 1
		indicators = append(indicators, "Very strong signal from unknown device")
	}
	
	// Type-specific threat assessment
	switch device.Type {
	case "wifi":
		threatLevel += s.assessWiFiThreat(device)
	case "bluetooth":
		threatLevel += s.assessBluetoothThreat(device)
	case "cellular":
		threatLevel += s.assessCellularThreat(device)
	}
	
	device.ThreatLevel = threatLevel
	
	// Generate alert if threat level is high
	if threatLevel >= s.config.Notifications.Alerts.ThreatLevel {
		alert := &models.Alert{
			ID:        s.generateAlertID(),
			DeviceID:  device.ID,
			Type:      "threat_detected",
			Severity:  s.getThreatSeverity(threatLevel),
			Title:     fmt.Sprintf("Threat detected: %s", device.Name),
			Message:   fmt.Sprintf("Device %s has threat level %d", device.MAC, threatLevel),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		
		s.alertChan <- alert
	}
}

// assessWiFiThreat performs Wi-Fi specific threat assessment
func (s *Scanner) assessWiFiThreat(device *models.Device) int {
	threatLevel := 0
	
	// Hidden SSID can be suspicious
	if device.Name == "" || device.Name == "<hidden>" {
		threatLevel += 1
	}
	
	// Suspicious SSID names
	suspiciousNames := []string{"camera", "spy", "hidden", "surveillance"}
	for _, suspicious := range suspiciousNames {
		if contains(device.Name, suspicious) {
			threatLevel += 3
		}
	}
	
	return threatLevel
}

// assessBluetoothThreat performs Bluetooth specific threat assessment
func (s *Scanner) assessBluetoothThreat(device *models.Device) int {
	threatLevel := 0
	
	// Anonymous or no name can be suspicious
	if device.Name == "" {
		threatLevel += 1
	}
	
	// Very strong signal might indicate tracking device
	if device.SignalLevel > -30 {
		threatLevel += 2
	}
	
	return threatLevel
}

// assessCellularThreat performs cellular specific threat assessment
func (s *Scanner) assessCellularThreat(device *models.Device) int {
	threatLevel := 0
	
	// Strong cellular signal without proper operator info is suspicious
	if device.SignalLevel > -50 && device.Manufacturer == "" {
		threatLevel += 4
	}
	
	return threatLevel
}

// continuousScanning performs continuous background scanning
func (s *Scanner) continuousScanning() {
	ticker := time.NewTicker(s.config.Core.ScanInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if s.isRunning {
				_, err := s.Scan("continuous", 10*time.Second)
				if err != nil {
					fmt.Printf("Continuous scan error: %v\n", err)
				}
			}
		}
	}
}

// processDevices processes devices from the device channel
func (s *Scanner) processDevices() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case device := <-s.deviceChan:
			// Additional processing can be added here
			fmt.Printf("Processed device: %s (%s)\n", device.Name, device.MAC)
		}
	}
}

// processAlerts processes alerts from the alert channel
func (s *Scanner) processAlerts() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case alert := <-s.alertChan:
			// Save alert to database
			if err := s.db.SaveAlert(alert); err != nil {
				fmt.Printf("Error saving alert: %v\n", err)
			}
			
			// Send notifications if enabled
			if s.config.Notifications.Enabled {
				s.sendNotification(alert)
			}
			
			fmt.Printf("Alert: %s - %s\n", alert.Title, alert.Message)
		}
	}
}

// processStatistics processes statistics from the stats channel
func (s *Scanner) processStatistics() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case stats := <-s.statsChan:
			fmt.Printf("Statistics: %+v\n", stats)
		}
	}
}

// sendNotification sends notifications (Discord, etc.)
func (s *Scanner) sendNotification(alert *models.Alert) {
	// TODO: Implement Discord webhook notifications
	if s.config.Notifications.Discord && s.config.Notifications.WebhookURL != "" {
		// Send Discord notification
	}
}

// Helper functions
func (s *Scanner) generateSessionID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *Scanner) generateAlertID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *Scanner) getThreatSeverity(level int) string {
	switch {
	case level >= 7:
		return "critical"
	case level >= 5:
		return "high"
	case level >= 3:
		return "medium"
	default:
		return "low"
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(substr) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// IsRunning returns whether the scanner is currently running
func (s *Scanner) IsRunning() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.isRunning
}

// GetActiveSessions returns currently active scan sessions
func (s *Scanner) GetActiveSessions() map[string]*models.ScanSession {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	
	sessions := make(map[string]*models.ScanSession)
	for k, v := range s.sessions {
		sessions[k] = v
	}
	return sessions
}
