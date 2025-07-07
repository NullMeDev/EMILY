package intelligence

import (
	"testing"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/database"
	"github.com/null/emily/internal/models"
)

func TestPatternMatcher(t *testing.T) {
	pm := NewPatternMatcher()
	
	// Test basic functionality
	if pm == nil {
		t.Fatal("PatternMatcher should not be nil")
	}
	
	// Create test device
	device := &models.Device{
		ID:           "test-device-1",
		Name:         "camera-wifi",
		Type:         "wifi",
		SignalLevel:  -30,
		SeenCount:    25,
		FirstSeen:    time.Now().Add(-2 * time.Hour),
		LastSeen:     time.Now(),
		ThreatLevel:  5,
	}
	
	// Test pattern analysis
	result := pm.AnalyzePatterns(device)
	if result == nil {
		t.Fatal("Pattern analysis result should not be nil")
	}
	
	if result.DeviceID != device.ID {
		t.Errorf("Expected device ID %s, got %s", device.ID, result.DeviceID)
	}
	
	// Check if any patterns were detected
	if len(result.DetectedPatterns) == 0 {
		t.Log("No patterns detected (this might be expected for simple test)")
	}
}

func TestRiskCalculator(t *testing.T) {
	rc := NewRiskCalculator()
	
	// Test basic functionality
	if rc == nil {
		t.Fatal("RiskCalculator should not be nil")
	}
	
	// Create test device
	device := &models.Device{
		ID:           "test-device-2",
		Name:         "suspicious-tracker",
		Type:         "bluetooth",
		SignalLevel:  -40,
		SeenCount:    30,
		FirstSeen:    time.Now().Add(-6 * time.Hour),
		LastSeen:     time.Now(),
		ThreatLevel:  7,
		Encryption:   "open",
	}
	
	// Create simple threat analysis result
	threatResult := &ThreatAnalysisResult{
		DeviceID:    device.ID,
		ThreatLevel: 7,
		Confidence:  0.8,
		ThreatTypes: []string{"tracking"},
		Indicators:  []string{"High signal strength", "Persistent presence"},
	}
	
	// Test risk calculation
	assessment := rc.CalculateRisk(device, threatResult)
	if assessment == nil {
		t.Fatal("Risk assessment should not be nil")
	}
	
	if assessment.DeviceID != device.ID {
		t.Errorf("Expected device ID %s, got %s", device.ID, assessment.DeviceID)
	}
	
	if assessment.OverallRiskScore < 0 || assessment.OverallRiskScore > 1 {
		t.Errorf("Risk score should be between 0 and 1, got %f", assessment.OverallRiskScore)
	}
	
	if assessment.RiskLevel == "" {
		t.Error("Risk level should not be empty")
	}
	
	t.Logf("Risk assessment: %s (score: %.2f, confidence: %.2f)", 
		assessment.RiskLevel, assessment.OverallRiskScore, assessment.Confidence)
}

func TestDeviceTracker(t *testing.T) {
	tracker := NewDeviceTracker()
	
	// Test basic functionality
	if tracker == nil {
		t.Fatal("DeviceTracker should not be nil")
	}
	
	// Create test device
	device := &models.Device{
		ID:           "test-device-3",
		Name:         "tracked-device",
		Type:         "wifi",
		SignalLevel:  -50,
		SeenCount:    1,
		FirstSeen:    time.Now(),
		LastSeen:     time.Now(),
		ThreatLevel:  3,
	}
	
	// Track device
	tracker.TrackDevice(device)
	
	// Retrieve tracked device
	tracked, exists := tracker.GetTrackedDevice(device.ID)
	if !exists {
		t.Fatal("Device should be tracked")
	}
	
	if tracked.Device.ID != device.ID {
		t.Errorf("Expected device ID %s, got %s", device.ID, tracked.Device.ID)
	}
	
	if len(tracked.History) == 0 {
		t.Error("Device should have observation history")
	}
	
	// Track device again to create more history
	device.SeenCount = 2
	device.SignalLevel = -45
	tracker.TrackDevice(device)
	
	tracked, _ = tracker.GetTrackedDevice(device.ID)
	if len(tracked.History) < 2 {
		t.Error("Device should have multiple observations")
	}
}

func TestIntelligenceEngineComponents(t *testing.T) {
	// Test that components can be created independently
	pm := NewPatternMatcher()
	rc := NewRiskCalculator()
	dt := NewDeviceTracker()
	
	if pm == nil || rc == nil || dt == nil {
		t.Fatal("All intelligence components should be creatable")
	}
	
	// Test pattern matcher statistics
	pmStats := pm.GetPatternStatistics()
	if pmStats["total_patterns"] == nil {
		t.Error("Pattern matcher should return statistics")
	}
	
	// Test risk calculator statistics
	rcStats := rc.GetRiskStatistics()
	if rcStats["total_factors"] == nil {
		t.Error("Risk calculator should return statistics")
	}
	
	// Test device tracker statistics
	dtStats := dt.GetDeviceStatistics()
	if dtStats["total_devices"] == nil {
		t.Error("Device tracker should return statistics")
	}
	
	t.Logf("Pattern matcher has %v patterns", pmStats["total_patterns"])
	t.Logf("Risk calculator has %v factors", rcStats["total_factors"])
	t.Logf("Device tracker tracking %v devices", dtStats["total_devices"])
}

func TestAlertManager(t *testing.T) {
	// Create minimal config for testing
	cfg := &config.Config{
		Notifications: config.NotificationConfig{
			Enabled: true,
			Alerts: struct {
				NewDevice     bool `mapstructure:"new_device" json:"new_device"`
				ThreatLevel   int  `mapstructure:"threat_level" json:"threat_level"`
				SignalLoss    bool `mapstructure:"signal_loss" json:"signal_loss"`
				Surveillance  bool `mapstructure:"surveillance" json:"surveillance"`
			}{
				ThreatLevel: 5,
			},
		},
	}
	
	// Create minimal database for testing (nil is acceptable for this test)
	var db *database.Database = nil
	
	am := NewAlertManager(cfg, db)
	if am == nil {
		t.Fatal("AlertManager should not be nil")
	}
	
	// Test that alert manager was created successfully
	t.Log("AlertManager created successfully")
}
