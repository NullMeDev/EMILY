package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/database"
	"github.com/null/emily/internal/models"
)

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

// Manager manages all scanners
type Manager struct {
	config      *config.Config
	db          *database.Database
	wifiScanner WiFiScanner
	btScanner   BluetoothScanner
	cellScanner CellularScanner
	nfcScanner  NFCScanner
	mu          sync.RWMutex
	running     bool
}

// NewManager creates a new scanner manager
func NewManager(cfg *config.Config, db *database.Database) (*Manager, error) {
	wifiScanner, err := NewWiFiScanner(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create WiFi scanner: %w", err)
	}

	btScanner, err := NewBluetoothScanner(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bluetooth scanner: %w", err)
	}

	cellScanner, err := NewCellularScanner(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create cellular scanner: %w", err)
	}

	nfcScanner, err := NewNFCScanner(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create NFC scanner: %w", err)
	}

	return &Manager{
		config:      cfg,
		db:          db,
		wifiScanner: wifiScanner,
		btScanner:   btScanner,
		cellScanner: cellScanner,
		nfcScanner:  nfcScanner,
	}, nil
}

// Start starts all scanners
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("scanner manager already running")
	}

	if m.config.Detection.WiFi.Enabled {
		if err := m.wifiScanner.Start(ctx); err != nil {
			return fmt.Errorf("failed to start WiFi scanner: %w", err)
		}
	}

	if m.config.Detection.Bluetooth.Enabled {
		if err := m.btScanner.Start(ctx); err != nil {
			return fmt.Errorf("failed to start Bluetooth scanner: %w", err)
		}
	}

	if m.config.Detection.Cellular.Enabled {
		if err := m.cellScanner.Start(ctx); err != nil {
			return fmt.Errorf("failed to start cellular scanner: %w", err)
		}
	}

	if m.config.Detection.NFC.Enabled {
		if err := m.nfcScanner.Start(ctx); err != nil {
			return fmt.Errorf("failed to start NFC scanner: %w", err)
		}
	}

	m.running = true
	return nil
}

// Stop stops all scanners
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	var errors []error

	if err := m.wifiScanner.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("WiFi scanner stop: %w", err))
	}

	if err := m.btScanner.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("Bluetooth scanner stop: %w", err))
	}

	if err := m.cellScanner.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("cellular scanner stop: %w", err))
	}

	if err := m.nfcScanner.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("NFC scanner stop: %w", err))
	}

	m.running = false

	if len(errors) > 0 {
		return fmt.Errorf("errors stopping scanners: %v", errors)
	}

	return nil
}

// ScanAll performs a scan with all enabled scanners
func (m *Manager) ScanAll(ctx context.Context, duration time.Duration) ([]models.Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.running {
		return nil, fmt.Errorf("scanner manager not running")
	}

	var allDevices []models.Device

	if m.config.Detection.WiFi.Enabled {
		devices, err := m.wifiScanner.Scan(ctx, duration)
		if err != nil {
			fmt.Printf("WiFi scan error: %v\n", err)
		} else {
			allDevices = append(allDevices, devices...)
		}
	}

	if m.config.Detection.Bluetooth.Enabled {
		devices, err := m.btScanner.Scan(ctx, duration)
		if err != nil {
			fmt.Printf("Bluetooth scan error: %v\n", err)
		} else {
			allDevices = append(allDevices, devices...)
		}
	}

	if m.config.Detection.Cellular.Enabled {
		devices, err := m.cellScanner.Scan(ctx, duration)
		if err != nil {
			fmt.Printf("Cellular scan error: %v\n", err)
		} else {
			allDevices = append(allDevices, devices...)
		}
	}

	if m.config.Detection.NFC.Enabled {
		devices, err := m.nfcScanner.Scan(ctx, duration)
		if err != nil {
			fmt.Printf("NFC scan error: %v\n", err)
		} else {
			allDevices = append(allDevices, devices...)
		}
	}

	return allDevices, nil
}

// IsRunning returns whether the manager is running
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// Scan performs a scan and returns a ScanResult for CLI compatibility
func (m *Manager) Scan(scanType string, duration time.Duration) (*models.ScanResult, error) {
	start := time.Now()
	ctx := context.Background()
	
	// Start scanner if not running
	if !m.IsRunning() {
		if err := m.Start(ctx); err != nil {
			return nil, fmt.Errorf("failed to start scanner: %w", err)
		}
		defer m.Stop() // Stop after scan completes
	}
	
	// Perform the actual scan
	devices, err := m.ScanAll(ctx, duration)
	if err != nil {
		return nil, err
	}
	
	// Assess threats for each device
	threats := make([]models.ThreatAssessment, 0)
	for _, device := range devices {
		if device.ThreatLevel > 0 {
			threat := models.ThreatAssessment{
				ID:          fmt.Sprintf("threat_%s_%d", device.ID, time.Now().Unix()),
				DeviceID:    device.ID,
				ThreatType:  m.classifyThreatType(device.Type, device.ThreatLevel),
				Score:       float64(device.ThreatLevel),
				Confidence:  0.8, // Default confidence
				Description: fmt.Sprintf("Potential threat detected from %s device %s", device.Type, device.Name),
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			threats = append(threats, threat)
		}
	}
	
	// Create scan result
	result := &models.ScanResult{
		SessionID:    fmt.Sprintf("scan_%d", time.Now().Unix()),
		Duration:     time.Since(start),
		DevicesFound: devices,
		ThreatsFound: threats,
		Statistics: map[string]interface{}{
			"scan_type":      scanType,
			"devices_count":  len(devices),
			"threats_count":  len(threats),
			"scan_duration": time.Since(start).String(),
		},
	}
	
	return result, nil
}

// classifyThreatType determines the threat type based on device type and threat level
func (m *Manager) classifyThreatType(deviceType string, threatLevel int) string {
	switch deviceType {
	case "wifi":
		if threatLevel >= 5 {
			return "rogue_ap"
		}
		return "suspicious_wifi"
	case "bluetooth":
		if threatLevel >= 5 {
			return "bluetooth_tracker"
		}
		return "suspicious_bluetooth"
	case "cellular":
		if threatLevel >= 5 {
			return "imsi_catcher"
		}
		return "suspicious_cellular"
	case "nfc":
		if threatLevel >= 5 {
			return "malicious_nfc"
		}
		return "suspicious_nfc"
	default:
		return "unknown_threat"
	}
}
