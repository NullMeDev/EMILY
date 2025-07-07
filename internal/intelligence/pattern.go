package intelligence

import (
	"math"
	"time"

	"github.com/null/emily/internal/models"
)

// PatternMatcher provides advanced pattern recognition for device behavior analysis
type PatternMatcher struct {
	patterns      []BehaviorPattern
	spatialCache  map[string][]SpatialEvent
	temporalCache map[string][]TemporalEvent
}

// BehaviorPattern represents a detectable behavioral pattern
type BehaviorPattern struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Type        string        `json:"type"` // spatial, temporal, signal, persistence
	Description string        `json:"description"`
	Indicators  []string      `json:"indicators"`
	Threshold   float64       `json:"threshold"`
	TimeWindow  time.Duration `json:"time_window"`
	Severity    int           `json:"severity"`
	Confidence  float64       `json:"confidence"`
}

// SpatialEvent represents a spatial occurrence event
type SpatialEvent struct {
	DeviceID     string    `json:"device_id"`
	Location     string    `json:"location"` // Could be coordinates or area identifier
	SignalLevel  int       `json:"signal_level"`
	Timestamp    time.Time `json:"timestamp"`
	Distance     float64   `json:"distance"` // Distance from reference point
	MovementType string    `json:"movement_type"` // static, mobile, periodic
}

// TemporalEvent represents a temporal occurrence event
type TemporalEvent struct {
	DeviceID    string    `json:"device_id"`
	EventType   string    `json:"event_type"` // appearance, disappearance, signal_change
	Timestamp   time.Time `json:"timestamp"`
	Duration    time.Duration `json:"duration"`
	Frequency   float64   `json:"frequency"`
	Periodicity string    `json:"periodicity"` // regular, irregular, burst
}

// PatternAnalysisResult represents the result of pattern analysis
type PatternAnalysisResult struct {
	DeviceID         string            `json:"device_id"`
	DetectedPatterns []DetectedPattern `json:"detected_patterns"`
	RiskScore        float64           `json:"risk_score"`
	Confidence       float64           `json:"confidence"`
	Recommendations  []string          `json:"recommendations"`
	Metadata         map[string]interface{} `json:"metadata"`
	AnalyzedAt       time.Time         `json:"analyzed_at"`
}

// DetectedPattern represents a pattern that was detected
type DetectedPattern struct {
	PatternID   string                 `json:"pattern_id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Confidence  float64                `json:"confidence"`
	Severity    int                    `json:"severity"`
	Evidence    []string               `json:"evidence"`
	Timeframe   time.Duration          `json:"timeframe"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewPatternMatcher creates a new pattern matcher
func NewPatternMatcher() *PatternMatcher {
	pm := &PatternMatcher{
		patterns:      make([]BehaviorPattern, 0),
		spatialCache:  make(map[string][]SpatialEvent),
		temporalCache: make(map[string][]TemporalEvent),
	}
	
	// Load built-in patterns
	pm.loadBuiltinPatterns()
	
	return pm
}

// AnalyzePatterns performs comprehensive pattern analysis on a device
func (pm *PatternMatcher) AnalyzePatterns(device *models.Device) *PatternAnalysisResult {
	result := &PatternAnalysisResult{
		DeviceID:         device.ID,
		DetectedPatterns: make([]DetectedPattern, 0),
		Recommendations:  make([]string, 0),
		Metadata:         make(map[string]interface{}),
		AnalyzedAt:       time.Now(),
	}

	// Update caches with device data
	pm.updateCaches(device)

	// Run pattern detection
	totalConfidence := 0.0
	totalRisk := 0.0
	patternCount := 0

	for _, pattern := range pm.patterns {
		detected := pm.detectPattern(device, &pattern)
		if detected != nil {
			result.DetectedPatterns = append(result.DetectedPatterns, *detected)
			totalConfidence += detected.Confidence
			totalRisk += float64(detected.Severity) * detected.Confidence
			patternCount++
		}
	}

	// Calculate overall scores
	if patternCount > 0 {
		result.Confidence = totalConfidence / float64(patternCount)
		result.RiskScore = totalRisk / float64(patternCount)
	}

	// Generate recommendations
	result.Recommendations = pm.generatePatternRecommendations(result)

	// Add metadata
	result.Metadata["pattern_count"] = patternCount
	result.Metadata["spatial_events"] = len(pm.spatialCache[device.ID])
	result.Metadata["temporal_events"] = len(pm.temporalCache[device.ID])

	return result
}

// detectPattern checks if a device matches a specific behavioral pattern
func (pm *PatternMatcher) detectPattern(device *models.Device, pattern *BehaviorPattern) *DetectedPattern {
	var confidence float64
	var evidence []string
	var metadata = make(map[string]interface{})

	switch pattern.Type {
	case "spatial":
		confidence, evidence = pm.detectSpatialPattern(device, pattern)
	case "temporal":
		confidence, evidence = pm.detectTemporalPattern(device, pattern)
	case "signal":
		confidence, evidence = pm.detectSignalPattern(device, pattern)
	case "persistence":
		confidence, evidence = pm.detectPersistencePattern(device, pattern)
	default:
		return nil
	}

	// Check if pattern threshold is met
	if confidence < pattern.Threshold {
		return nil
	}

	return &DetectedPattern{
		PatternID:  pattern.ID,
		Name:       pattern.Name,
		Type:       pattern.Type,
		Confidence: confidence,
		Severity:   pattern.Severity,
		Evidence:   evidence,
		Timeframe:  pattern.TimeWindow,
		Metadata:   metadata,
	}
}

// detectSpatialPattern analyzes spatial behavior patterns
func (pm *PatternMatcher) detectSpatialPattern(device *models.Device, pattern *BehaviorPattern) (float64, []string) {
	events := pm.spatialCache[device.ID]
	evidence := make([]string, 0)
	
	if len(events) < 2 {
		return 0.0, evidence
	}

	switch pattern.ID {
	case "following_pattern":
		return pm.analyzeFollowingPattern(events, evidence)
	case "perimeter_monitoring":
		return pm.analyzePerimeterPattern(events, evidence)
	case "static_surveillance":
		return pm.analyzeStaticPattern(events, evidence)
	default:
		return 0.0, evidence
	}
}

// detectTemporalPattern analyzes temporal behavior patterns
func (pm *PatternMatcher) detectTemporalPattern(device *models.Device, pattern *BehaviorPattern) (float64, []string) {
	events := pm.temporalCache[device.ID]
	evidence := make([]string, 0)
	
	if len(events) < 2 {
		return 0.0, evidence
	}

	switch pattern.ID {
	case "scheduled_surveillance":
		return pm.analyzeScheduledPattern(events, evidence)
	case "burst_activity":
		return pm.analyzeBurstPattern(events, evidence)
	case "periodic_tracking":
		return pm.analyzePeriodicPattern(events, evidence)
	default:
		return 0.0, evidence
	}
}

// detectSignalPattern analyzes signal-based patterns
func (pm *PatternMatcher) detectSignalPattern(device *models.Device, pattern *BehaviorPattern) (float64, []string) {
	evidence := make([]string, 0)
	
	switch pattern.ID {
	case "signal_spoofing":
		return pm.analyzeSignalSpoofing(device, evidence)
	case "proximity_tracking":
		return pm.analyzeProximityPattern(device, evidence)
	case "signal_jamming":
		return pm.analyzeJammingPattern(device, evidence)
	default:
		return 0.0, evidence
	}
}

// detectPersistencePattern analyzes persistence behavior patterns
func (pm *PatternMatcher) detectPersistencePattern(device *models.Device, pattern *BehaviorPattern) (float64, []string) {
	evidence := make([]string, 0)
	
	switch pattern.ID {
	case "persistent_presence":
		return pm.analyzePersistentPresence(device, evidence)
	case "intermittent_tracking":
		return pm.analyzeIntermittentPattern(device, evidence)
	default:
		return 0.0, evidence
	}
}

// Specific pattern analysis functions

func (pm *PatternMatcher) analyzeFollowingPattern(events []SpatialEvent, evidence []string) (float64, []string) {
	// Analyze if device is following a predictable path
	if len(events) < 3 {
		return 0.0, evidence
	}

	// Calculate movement consistency
	distances := make([]float64, len(events)-1)
	for i := 1; i < len(events); i++ {
		distances[i-1] = events[i].Distance - events[i-1].Distance
	}

	// Check for consistent movement pattern
	variance := pm.calculateVariance(distances)
	if variance < 0.1 { // Low variance indicates consistent movement
		evidence = append(evidence, "Consistent movement pattern detected")
		return 0.8, evidence
	}

	return 0.0, evidence
}

func (pm *PatternMatcher) analyzePerimeterPattern(events []SpatialEvent, evidence []string) (float64, []string) {
	// Look for devices monitoring perimeter
	staticCount := 0
	for _, event := range events {
		if event.MovementType == "static" {
			staticCount++
		}
	}

	if float64(staticCount)/float64(len(events)) > 0.7 {
		evidence = append(evidence, "Device maintaining static position")
		return 0.7, evidence
	}

	return 0.0, evidence
}

func (pm *PatternMatcher) analyzeStaticPattern(events []SpatialEvent, evidence []string) (float64, []string) {
	// Analyze static surveillance patterns
	if len(events) < 5 {
		return 0.0, evidence
	}

	// Check for long-term static presence
	duration := events[len(events)-1].Timestamp.Sub(events[0].Timestamp)
	if duration > 30*time.Minute {
		evidence = append(evidence, "Long-term static presence detected")
		return 0.9, evidence
	}

	return 0.0, evidence
}

func (pm *PatternMatcher) analyzeScheduledPattern(events []TemporalEvent, evidence []string) (float64, []string) {
	// Look for scheduled/regular patterns
	if len(events) < 3 {
		return 0.0, evidence
	}

	// Check for regular timing
	intervals := make([]time.Duration, len(events)-1)
	for i := 1; i < len(events); i++ {
		intervals[i-1] = events[i].Timestamp.Sub(events[i-1].Timestamp)
	}

	// Check for regularity
	avgInterval := pm.calculateAverageInterval(intervals)
	regularCount := 0
	for _, interval := range intervals {
		if math.Abs(interval.Seconds()-avgInterval.Seconds()) < 300 { // Within 5 minutes
			regularCount++
		}
	}

	if float64(regularCount)/float64(len(intervals)) > 0.6 {
		evidence = append(evidence, "Regular scheduling pattern detected")
		return 0.8, evidence
	}

	return 0.0, evidence
}

func (pm *PatternMatcher) analyzeBurstPattern(events []TemporalEvent, evidence []string) (float64, []string) {
	// Look for burst activity patterns
	if len(events) < 5 {
		return 0.0, evidence
	}

	// Check for clustered events
	burstCount := 0
	for i := 1; i < len(events); i++ {
		if events[i].Timestamp.Sub(events[i-1].Timestamp) < 5*time.Minute {
			burstCount++
		}
	}

	if float64(burstCount)/float64(len(events)) > 0.5 {
		evidence = append(evidence, "Burst activity pattern detected")
		return 0.7, evidence
	}

	return 0.0, evidence
}

func (pm *PatternMatcher) analyzePeriodicPattern(events []TemporalEvent, evidence []string) (float64, []string) {
	// Similar to scheduled but looking for periodic behavior
	return pm.analyzeScheduledPattern(events, evidence)
}

func (pm *PatternMatcher) analyzeSignalSpoofing(device *models.Device, evidence []string) (float64, []string) {
	// Check for signal spoofing indicators
	if device.SignalLevel > -30 && device.Type == "wifi" {
		evidence = append(evidence, "Unusually strong WiFi signal")
		return 0.6, evidence
	}

	return 0.0, evidence
}

func (pm *PatternMatcher) analyzeProximityPattern(device *models.Device, evidence []string) (float64, []string) {
	// Check for proximity tracking patterns
	if device.SignalLevel > -50 && device.SeenCount > 10 {
		evidence = append(evidence, "Persistent close proximity")
		return 0.7, evidence
	}

	return 0.0, evidence
}

func (pm *PatternMatcher) analyzeJammingPattern(device *models.Device, evidence []string) (float64, []string) {
	// Look for jamming patterns (would need more sophisticated analysis)
	return 0.0, evidence
}

func (pm *PatternMatcher) analyzePersistentPresence(device *models.Device, evidence []string) (float64, []string) {
	// Check for persistent presence patterns
	if device.SeenCount > 20 && time.Since(device.LastSeen) < 5*time.Minute {
		evidence = append(evidence, "Device showing persistent presence")
		return 0.8, evidence
	}

	return 0.0, evidence
}

func (pm *PatternMatcher) analyzeIntermittentPattern(device *models.Device, evidence []string) (float64, []string) {
	// Look for intermittent tracking patterns
	if device.SeenCount > 5 && device.SeenCount < 15 {
		evidence = append(evidence, "Intermittent presence pattern")
		return 0.6, evidence
	}

	return 0.0, evidence
}

// Helper functions

func (pm *PatternMatcher) updateCaches(device *models.Device) {
	// Update spatial cache
	spatialEvent := SpatialEvent{
		DeviceID:     device.ID,
		Location:     "unknown", // Would be populated with actual location data
		SignalLevel:  device.SignalLevel,
		Timestamp:    time.Now(),
		Distance:     0.0, // Would be calculated based on signal strength
		MovementType: pm.determineMovementType(device),
	}

	pm.spatialCache[device.ID] = append(pm.spatialCache[device.ID], spatialEvent)

	// Update temporal cache
	temporalEvent := TemporalEvent{
		DeviceID:    device.ID,
		EventType:   "detection",
		Timestamp:   time.Now(),
		Duration:    time.Since(device.LastSeen),
		Frequency:   float64(device.SeenCount),
		Periodicity: "irregular", // Would be calculated based on timing analysis
	}

	pm.temporalCache[device.ID] = append(pm.temporalCache[device.ID], temporalEvent)

	// Limit cache size to prevent memory issues
	maxCacheSize := 100
	if len(pm.spatialCache[device.ID]) > maxCacheSize {
		pm.spatialCache[device.ID] = pm.spatialCache[device.ID][len(pm.spatialCache[device.ID])-maxCacheSize:]
	}
	if len(pm.temporalCache[device.ID]) > maxCacheSize {
		pm.temporalCache[device.ID] = pm.temporalCache[device.ID][len(pm.temporalCache[device.ID])-maxCacheSize:]
	}
}

func (pm *PatternMatcher) determineMovementType(device *models.Device) string {
	// Simple movement type determination based on signal stability
	if device.SeenCount > 5 && device.SignalLevel > -60 {
		return "static"
	}
	return "mobile"
}

func (pm *PatternMatcher) calculateVariance(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}

	mean := 0.0
	for _, v := range values {
		mean += v
	}
	mean /= float64(len(values))

	variance := 0.0
	for _, v := range values {
		variance += (v - mean) * (v - mean)
	}
	variance /= float64(len(values))

	return variance
}

func (pm *PatternMatcher) calculateAverageInterval(intervals []time.Duration) time.Duration {
	if len(intervals) == 0 {
		return 0
	}

	total := time.Duration(0)
	for _, interval := range intervals {
		total += interval
	}
	return total / time.Duration(len(intervals))
}

func (pm *PatternMatcher) generatePatternRecommendations(result *PatternAnalysisResult) []string {
	recommendations := make([]string, 0)

	// High-risk patterns
	highRiskPatterns := []string{"following_pattern", "perimeter_monitoring", "signal_spoofing"}
	for _, pattern := range result.DetectedPatterns {
		for _, highRisk := range highRiskPatterns {
			if pattern.PatternID == highRisk && pattern.Confidence > 0.7 {
				recommendations = append(recommendations, "HIGH RISK: "+pattern.Name+" detected - consider immediate countermeasures")
			}
		}
	}

	// Medium-risk patterns
	mediumRiskPatterns := []string{"scheduled_surveillance", "persistent_presence"}
	for _, pattern := range result.DetectedPatterns {
		for _, mediumRisk := range mediumRiskPatterns {
			if pattern.PatternID == mediumRisk && pattern.Confidence > 0.6 {
				recommendations = append(recommendations, "MEDIUM RISK: "+pattern.Name+" detected - increase monitoring")
			}
		}
	}

	// General recommendations
	if result.RiskScore > 0.8 {
		recommendations = append(recommendations, "Multiple high-risk patterns detected - consider changing location")
	} else if result.RiskScore > 0.5 {
		recommendations = append(recommendations, "Moderate risk patterns detected - maintain awareness")
	}

	return recommendations
}

func (pm *PatternMatcher) loadBuiltinPatterns() {
	// Following pattern
	followingPattern := BehaviorPattern{
		ID:          "following_pattern",
		Name:        "Following Pattern",
		Type:        "spatial",
		Description: "Device exhibiting following behavior",
		Indicators:  []string{"consistent_movement", "proximity_maintenance"},
		Threshold:   0.7,
		TimeWindow:  30 * time.Minute,
		Severity:    8,
		Confidence:  0.8,
	}

	// Perimeter monitoring
	perimeterPattern := BehaviorPattern{
		ID:          "perimeter_monitoring",
		Name:        "Perimeter Monitoring",
		Type:        "spatial",
		Description: "Device monitoring perimeter or boundary",
		Indicators:  []string{"static_position", "boundary_alignment"},
		Threshold:   0.6,
		TimeWindow:  60 * time.Minute,
		Severity:    7,
		Confidence:  0.7,
	}

	// Scheduled surveillance
	scheduledPattern := BehaviorPattern{
		ID:          "scheduled_surveillance",
		Name:        "Scheduled Surveillance",
		Type:        "temporal",
		Description: "Device appearing on regular schedule",
		Indicators:  []string{"regular_timing", "predictable_presence"},
		Threshold:   0.6,
		TimeWindow:  24 * time.Hour,
		Severity:    6,
		Confidence:  0.8,
	}

	// Persistent presence
	persistentPattern := BehaviorPattern{
		ID:          "persistent_presence",
		Name:        "Persistent Presence",
		Type:        "persistence",
		Description: "Device maintaining persistent presence",
		Indicators:  []string{"high_seen_count", "recent_activity"},
		Threshold:   0.7,
		TimeWindow:  2 * time.Hour,
		Severity:    5,
		Confidence:  0.8,
	}

	// Signal spoofing
	spoofingPattern := BehaviorPattern{
		ID:          "signal_spoofing",
		Name:        "Signal Spoofing",
		Type:        "signal",
		Description: "Device potentially spoofing signal characteristics",
		Indicators:  []string{"unusual_signal_strength", "suspicious_characteristics"},
		Threshold:   0.6,
		TimeWindow:  15 * time.Minute,
		Severity:    8,
		Confidence:  0.6,
	}

	pm.patterns = []BehaviorPattern{
		followingPattern,
		perimeterPattern,
		scheduledPattern,
		persistentPattern,
		spoofingPattern,
	}
}

// ClearCache clears the pattern matcher caches
func (pm *PatternMatcher) ClearCache() {
	pm.spatialCache = make(map[string][]SpatialEvent)
	pm.temporalCache = make(map[string][]TemporalEvent)
}

// GetPatternStatistics returns statistics about detected patterns
func (pm *PatternMatcher) GetPatternStatistics() map[string]interface{} {
	stats := make(map[string]interface{})
	
	stats["total_patterns"] = len(pm.patterns)
	stats["cached_devices"] = len(pm.spatialCache)
	
	// Pattern type breakdown
	typeCount := make(map[string]int)
	for _, pattern := range pm.patterns {
		typeCount[pattern.Type]++
	}
	stats["pattern_types"] = typeCount
	
	return stats
}
