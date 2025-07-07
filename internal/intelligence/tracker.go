package intelligence

import (
	"fmt"
	"sync"
	"time"

	"github.com/null/emily/internal/models"
)

// DeviceTracker monitors device behavior and patterns over time
type DeviceTracker struct {
	devices map[string]*TrackedDevice
	mutex   sync.RWMutex
}

// TrackedDevice represents a device with enhanced tracking information
type TrackedDevice struct {
	Device         *models.Device           `json:"device"`
	History        []DeviceObservation      `json:"history"`
	Patterns       []TrackingPattern        `json:"patterns"`
	RiskScore      float64                  `json:"risk_score"`
	LastAnalyzed   time.Time                `json:"last_analyzed"`
	Metadata       map[string]interface{}   `json:"metadata"`
	
	// Behavioral metrics
	AppearanceCount    int           `json:"appearance_count"`
	AvgSessionDuration time.Duration `json:"avg_session_duration"`
	SignalVariance     float64       `json:"signal_variance"`
	LocationChanges    int           `json:"location_changes"`
	TimeWindows        []TimeWindow  `json:"time_windows"`
}

// DeviceObservation represents a single observation of a device
type DeviceObservation struct {
	Timestamp   time.Time              `json:"timestamp"`
	SignalLevel int                    `json:"signal_level"`
	Location    *Location              `json:"location,omitempty"`
	Context     map[string]interface{} `json:"context"`
	EventType   string                 `json:"event_type"` // appeared, disappeared, moved, changed
}

// TrackingPattern represents detected behavioral patterns in device tracking
type TrackingPattern struct {
	Type        string                 `json:"type"`        // persistent, transient, stalking, roaming
	Confidence  float64                `json:"confidence"`  // 0-1
	StartTime   time.Time              `json:"start_time"`
	EndTime     *time.Time             `json:"end_time,omitempty"`
	Indicators  []string               `json:"indicators"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// TimeWindow represents a time window when device is typically active
type TimeWindow struct {
	StartHour int     `json:"start_hour"` // 0-23
	EndHour   int     `json:"end_hour"`   // 0-23
	DaysOfWeek []int  `json:"days_of_week"` // 0=Sunday, 1=Monday, etc.
	Frequency float64 `json:"frequency"`  // 0-1, how often seen in this window
}

// Location represents a geographical location with uncertainty
type Location struct {
	Latitude   float64 `json:"latitude"`
	Longitude  float64 `json:"longitude"`
	Accuracy   float64 `json:"accuracy"`   // in meters
	Source     string  `json:"source"`     // gps, wifi, triangulation, estimated
	Timestamp  time.Time `json:"timestamp"`
}

// NewDeviceTracker creates a new device tracker
func NewDeviceTracker() *DeviceTracker {
	return &DeviceTracker{
		devices: make(map[string]*TrackedDevice),
	}
}

// TrackDevice adds or updates device tracking information
func (dt *DeviceTracker) TrackDevice(device *models.Device) {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	tracked, exists := dt.devices[device.ID]
	if !exists {
		tracked = &TrackedDevice{
			Device:          device,
			History:         make([]DeviceObservation, 0),
			Patterns:        make([]TrackingPattern, 0),
			TimeWindows:     make([]TimeWindow, 0),
			Metadata:        make(map[string]interface{}),
			AppearanceCount: 1,
		}
		dt.devices[device.ID] = tracked
	}

	// Add new observation
	observation := DeviceObservation{
		Timestamp:   time.Now(),
		SignalLevel: device.SignalLevel,
		EventType:   "observed",
		Context:     make(map[string]interface{}),
	}

	tracked.History = append(tracked.History, observation)
	tracked.Device = device // Update with latest device info
	tracked.AppearanceCount++

	// Analyze patterns
	dt.analyzeDevicePatterns(tracked)
	
	// Calculate risk score
	tracked.RiskScore = dt.calculateRiskScore(tracked)
	tracked.LastAnalyzed = time.Now()
}

// GetTrackedDevice returns tracking information for a device
func (dt *DeviceTracker) GetTrackedDevice(deviceID string) (*TrackedDevice, bool) {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()
	
	tracked, exists := dt.devices[deviceID]
	return tracked, exists
}

// GetAllTrackedDevices returns all tracked devices
func (dt *DeviceTracker) GetAllTrackedDevices() map[string]*TrackedDevice {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()
	
	result := make(map[string]*TrackedDevice)
	for k, v := range dt.devices {
		result[k] = v
	}
	return result
}

// analyzeDevicePatterns analyzes behavioral patterns for a tracked device
func (dt *DeviceTracker) analyzeDevicePatterns(tracked *TrackedDevice) {
	if len(tracked.History) < 2 {
		return
	}

	// Analyze persistence pattern
	dt.analyzePersistencePattern(tracked)
	
	// Analyze temporal patterns
	dt.analyzeTemporalPatterns(tracked)
	
	// Analyze signal patterns
	dt.analyzeSignalPatterns(tracked)
	
	// Analyze movement patterns
	dt.analyzeMovementPatterns(tracked)
}

// analyzePersistencePattern determines if device shows persistent behavior
func (dt *DeviceTracker) analyzePersistencePattern(tracked *TrackedDevice) {
	if len(tracked.History) < 5 {
		return
	}

	// Check if device appears consistently over time
	now := time.Now()
	observations := tracked.History
	
	// Look at last 24 hours
	recentObservations := 0
	for _, obs := range observations {
		if now.Sub(obs.Timestamp) <= 24*time.Hour {
			recentObservations++
		}
	}

	// If seen more than 5 times in 24 hours, consider persistent
	if recentObservations >= 5 {
		pattern := TrackingPattern{
			Type:       "persistent",
			Confidence: float64(recentObservations) / 24.0, // rough confidence
			StartTime:  observations[0].Timestamp,
			Indicators: []string{"Device seen frequently over extended period"},
			Metadata:   map[string]interface{}{"observation_count": recentObservations},
		}
		
		if pattern.Confidence > 1.0 {
			pattern.Confidence = 1.0
		}
		
		tracked.Patterns = append(tracked.Patterns, pattern)
	}
}

// analyzeTemporalPatterns analyzes time-based patterns
func (dt *DeviceTracker) analyzeTemporalPatterns(tracked *TrackedDevice) {
	observations := tracked.History
	if len(observations) < 3 {
		return
	}

	// Analyze time windows when device is active
	hourCounts := make(map[int]int)
	dayOfWeekCounts := make(map[int]int)

	for _, obs := range observations {
		hour := obs.Timestamp.Hour()
		dayOfWeek := int(obs.Timestamp.Weekday())
		
		hourCounts[hour]++
		dayOfWeekCounts[dayOfWeek]++
	}

	// Find peak hours
	maxHourCount := 0
	peakHour := 0
	for hour, count := range hourCounts {
		if count > maxHourCount {
			maxHourCount = count
			peakHour = hour
		}
	}

	// If there's a clear pattern, add it
	if maxHourCount >= 3 && float64(maxHourCount)/float64(len(observations)) >= 0.3 {
		pattern := TrackingPattern{
			Type:       "temporal",
			Confidence: float64(maxHourCount) / float64(len(observations)),
			StartTime:  observations[0].Timestamp,
			Indicators: []string{fmt.Sprintf("Device most active during hour %d", peakHour)},
			Metadata: map[string]interface{}{
				"peak_hour":      peakHour,
				"peak_frequency": maxHourCount,
			},
		}
		tracked.Patterns = append(tracked.Patterns, pattern)
	}
}

// analyzeSignalPatterns analyzes signal strength patterns
func (dt *DeviceTracker) analyzeSignalPatterns(tracked *TrackedDevice) {
	observations := tracked.History
	if len(observations) < 3 {
		return
	}

	// Calculate signal variance
	var sum, sumSquares float64
	for _, obs := range observations {
		signal := float64(obs.SignalLevel)
		sum += signal
		sumSquares += signal * signal
	}

	n := float64(len(observations))
	mean := sum / n
	variance := (sumSquares / n) - (mean * mean)
	tracked.SignalVariance = variance

	// Check for unusual signal patterns
	if variance < 10 { // Very stable signal
		pattern := TrackingPattern{
			Type:       "stable_signal",
			Confidence: 1.0 - (variance / 100.0), // Higher confidence for lower variance
			StartTime:  observations[0].Timestamp,
			Indicators: []string{"Device shows very stable signal strength"},
			Metadata:   map[string]interface{}{"signal_variance": variance},
		}
		tracked.Patterns = append(tracked.Patterns, pattern)
	} else if variance > 100 { // Very unstable signal
		pattern := TrackingPattern{
			Type:       "mobile_device",
			Confidence: variance / 500.0, // Confidence increases with variance
			StartTime:  observations[0].Timestamp,
			Indicators: []string{"Device shows high signal variability suggesting movement"},
			Metadata:   map[string]interface{}{"signal_variance": variance},
		}
		if pattern.Confidence > 1.0 {
			pattern.Confidence = 1.0
		}
		tracked.Patterns = append(tracked.Patterns, pattern)
	}
}

// analyzeMovementPatterns analyzes movement and location patterns
func (dt *DeviceTracker) analyzeMovementPatterns(tracked *TrackedDevice) {
	// This would require location data which we don't have yet
	// Placeholder for future enhancement
}

// calculateRiskScore calculates overall risk score for a device
func (dt *DeviceTracker) calculateRiskScore(tracked *TrackedDevice) float64 {
	device := tracked.Device
	baseRisk := float64(device.ThreatLevel) / 10.0

	// Factor in patterns
	patternRisk := 0.0
	for _, pattern := range tracked.Patterns {
		switch pattern.Type {
		case "persistent":
			// Persistent devices might be surveillance
			patternRisk += pattern.Confidence * 0.3
		case "stable_signal":
			// Very stable signal might indicate fixed surveillance
			patternRisk += pattern.Confidence * 0.2
		case "temporal":
			// Temporal patterns might indicate scheduled surveillance
			patternRisk += pattern.Confidence * 0.1
		}
	}

	// Factor in behavior metrics
	behaviorRisk := 0.0
	
	// High appearance count with low seen count might indicate scanning/tracking
	if tracked.AppearanceCount > 10 && device.SeenCount < 5 {
		behaviorRisk += 0.2
	}

	// Strong signal from unknown/unwhitelisted device
	if device.SignalLevel > -40 && !device.IsWhitelisted {
		behaviorRisk += 0.3
	}

	totalRisk := baseRisk + patternRisk + behaviorRisk
	if totalRisk > 1.0 {
		totalRisk = 1.0
	}

	return totalRisk
}

// CleanupOldData removes old tracking data to prevent memory leaks
func (dt *DeviceTracker) CleanupOldData(maxAge time.Duration) {
	dt.mutex.Lock()
	defer dt.mutex.Unlock()

	cutoff := time.Now().Add(-maxAge)
	
	for deviceID, tracked := range dt.devices {
		// Remove old observations
		newHistory := make([]DeviceObservation, 0)
		for _, obs := range tracked.History {
			if obs.Timestamp.After(cutoff) {
				newHistory = append(newHistory, obs)
			}
		}
		tracked.History = newHistory

		// Remove device if no recent observations
		if len(newHistory) == 0 && tracked.Device.LastSeen.Before(cutoff) {
			delete(dt.devices, deviceID)
		}
	}
}

// GetSuspiciousDevices returns devices with high risk scores
func (dt *DeviceTracker) GetSuspiciousDevices(threshold float64) []*TrackedDevice {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()

	suspicious := make([]*TrackedDevice, 0)
	for _, tracked := range dt.devices {
		if tracked.RiskScore >= threshold {
			suspicious = append(suspicious, tracked)
		}
	}

	return suspicious
}

// GetDeviceStatistics returns statistics about tracked devices
func (dt *DeviceTracker) GetDeviceStatistics() map[string]interface{} {
	dt.mutex.RLock()
	defer dt.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_devices":     len(dt.devices),
		"high_risk_devices": 0,
		"persistent_devices": 0,
		"mobile_devices":    0,
		"avg_risk_score":    0.0,
	}

	totalRisk := 0.0
	for _, tracked := range dt.devices {
		totalRisk += tracked.RiskScore
		
		if tracked.RiskScore >= 0.7 {
			stats["high_risk_devices"] = stats["high_risk_devices"].(int) + 1
		}

		for _, pattern := range tracked.Patterns {
			switch pattern.Type {
			case "persistent":
				stats["persistent_devices"] = stats["persistent_devices"].(int) + 1
			case "mobile_device":
				stats["mobile_devices"] = stats["mobile_devices"].(int) + 1
			}
		}
	}

	if len(dt.devices) > 0 {
		stats["avg_risk_score"] = totalRisk / float64(len(dt.devices))
	}

	return stats
}
