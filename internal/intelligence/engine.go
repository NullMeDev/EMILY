package intelligence

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/database"
	"github.com/null/emily/internal/models"
)

// IntelligenceEngine provides advanced threat analysis and pattern recognition
type IntelligenceEngine struct {
	config         *config.Config
	db             *database.Database
	threatProfiles map[string]*ThreatProfile
	behaviorRules  []*BehaviorRule
	correlations   map[string]*ThreatCorrelation
	mutex          sync.RWMutex
	
	// Analytics
	deviceTracker  *DeviceTracker
	alertManager   *AlertManager
	patternMatcher *PatternMatcher
	riskCalculator *RiskCalculator
	mlClassifier   *MLClassifier
}

// ThreatProfile represents a known threat signature
type ThreatProfile struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // surveillance, tracking, rogue_ap, imsi_catcher, etc.
	Severity    int                    `json:"severity"` // 1-10
	Indicators  []ThreatIndicator      `json:"indicators"`
	Patterns    []DevicePattern        `json:"patterns"`
	Metadata    map[string]interface{} `json:"metadata"`
	LastUpdated time.Time              `json:"last_updated"`
}

// ThreatIndicator represents a specific indicator of compromise
type ThreatIndicator struct {
	Type        string  `json:"type"`        // signal, behavior, network, device
	Field       string  `json:"field"`       // signal_level, ssid, manufacturer, etc.
	Operator    string  `json:"operator"`    // equals, contains, greater_than, pattern
	Value       string  `json:"value"`       // threshold or pattern value
	Weight      float64 `json:"weight"`      // importance weight (0-1)
	Description string  `json:"description"` // human readable description
}

// DevicePattern represents behavioral patterns for devices
type DevicePattern struct {
	TimeWindow    time.Duration `json:"time_window"`
	MinOccurrence int           `json:"min_occurrence"`
	MaxGap        time.Duration `json:"max_gap"`
	Conditions    []string      `json:"conditions"`
	Score         float64       `json:"score"`
}

// BehaviorRule represents rules for detecting suspicious behavior
type BehaviorRule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Conditions  []RuleCondition `json:"conditions"`
	Action      string        `json:"action"` // alert, log, block, investigate
	Severity    int           `json:"severity"`
	Enabled     bool          `json:"enabled"`
}

// RuleCondition represents a condition in a behavior rule
type RuleCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Logic    string      `json:"logic"` // AND, OR, NOT
}

// ThreatCorrelation tracks related threats and events
type ThreatCorrelation struct {
	ID          string               `json:"id"`
	ThreatType  string               `json:"threat_type"`
	Devices     []string             `json:"devices"`
	Events      []CorrelationEvent   `json:"events"`
	Score       float64              `json:"score"`
	Confidence  float64              `json:"confidence"`
	StartTime   time.Time            `json:"start_time"`
	LastUpdate  time.Time            `json:"last_update"`
	Status      string               `json:"status"` // active, resolved, investigating
	Indicators  []string             `json:"indicators"`
}

// CorrelationEvent represents an event in a threat correlation
type CorrelationEvent struct {
	DeviceID    string                 `json:"device_id"`
	EventType   string                 `json:"event_type"`
	Timestamp   time.Time              `json:"timestamp"`
	Data        map[string]interface{} `json:"data"`
	Severity    int                    `json:"severity"`
}

// ThreatAnalysisResult represents the result of threat analysis
type ThreatAnalysisResult struct {
	DeviceID       string                 `json:"device_id"`
	ThreatLevel    int                    `json:"threat_level"`
	ThreatTypes    []string               `json:"threat_types"`
	Confidence     float64                `json:"confidence"`
	Indicators     []string               `json:"indicators"`
	Recommendations []string              `json:"recommendations"`
	Correlations   []string               `json:"correlations"`
	Metadata       map[string]interface{} `json:"metadata"`
	AnalyzedAt     time.Time              `json:"analyzed_at"`
}

// NewIntelligenceEngine creates a new intelligence engine
func NewIntelligenceEngine(cfg *config.Config, db *database.Database) (*IntelligenceEngine, error) {
	engine := &IntelligenceEngine{
		config:         cfg,
		db:             db,
		threatProfiles: make(map[string]*ThreatProfile),
		behaviorRules:  make([]*BehaviorRule, 0),
		correlations:   make(map[string]*ThreatCorrelation),
		deviceTracker:  NewDeviceTracker(),
		alertManager:   NewAlertManager(cfg, db),
		patternMatcher: NewPatternMatcher(),
		riskCalculator: NewRiskCalculator(),
		mlClassifier:   NewMLClassifier(),
	}

	// Load built-in threat profiles
	if err := engine.loadBuiltinThreatProfiles(); err != nil {
		return nil, fmt.Errorf("failed to load threat profiles: %w", err)
	}

	// Load behavior rules
	if err := engine.loadBehaviorRules(); err != nil {
		return nil, fmt.Errorf("failed to load behavior rules: %w", err)
	}

	return engine, nil
}

// AnalyzeDevice performs comprehensive threat analysis on a device
func (ie *IntelligenceEngine) AnalyzeDevice(device *models.Device) (*ThreatAnalysisResult, error) {
	ie.mutex.Lock()
	defer ie.mutex.Unlock()

	result := &ThreatAnalysisResult{
		DeviceID:        device.ID,
		ThreatTypes:     make([]string, 0),
		Indicators:      make([]string, 0),
		Recommendations: make([]string, 0),
		Correlations:    make([]string, 0),
		Metadata:        make(map[string]interface{}),
		AnalyzedAt:      time.Now(),
	}

	// Track device behavior
	ie.deviceTracker.TrackDevice(device)

	// Analyze against threat profiles
	threatScore := 0.0
	confidenceSum := 0.0
	matchCount := 0

	for _, profile := range ie.threatProfiles {
		match, confidence := ie.evaluateThreatProfile(device, profile)
		if match {
			result.ThreatTypes = append(result.ThreatTypes, profile.Type)
			threatScore += float64(profile.Severity) * confidence
			confidenceSum += confidence
			matchCount++

			// Add specific indicators
			for _, indicator := range profile.Indicators {
				if ie.evaluateIndicator(device, &indicator) {
					result.Indicators = append(result.Indicators, indicator.Description)
				}
			}
		}
	}

	// Calculate overall threat level and confidence
	if matchCount > 0 {
		result.ThreatLevel = int(threatScore / float64(matchCount))
		result.Confidence = confidenceSum / float64(matchCount)
	}

	// Apply behavior rule analysis
	behaviorThreat, behaviorIndicators := ie.evaluateBehaviorRules(device)
	result.ThreatLevel = int(math.Max(float64(result.ThreatLevel), float64(behaviorThreat)))
	result.Indicators = append(result.Indicators, behaviorIndicators...)

	// Check for correlations with other devices
	correlations := ie.findThreatCorrelations(device)
	for _, corr := range correlations {
		result.Correlations = append(result.Correlations, corr.ID)
		result.ThreatLevel = int(math.Max(float64(result.ThreatLevel), corr.Score))
	}

	// Generate recommendations
	result.Recommendations = ie.generateRecommendations(result)

	// Risk assessment
	riskAssessment := ie.riskCalculator.CalculateRisk(device, result)
	result.Metadata["risk_assessment"] = riskAssessment

	// Pattern analysis
	patterns := ie.patternMatcher.AnalyzePatterns(device)
	result.Metadata["patterns"] = patterns

	// Machine learning classification
	mlResults, err := ie.mlClassifier.ClassifyDevice(device)
	if err == nil && len(mlResults) > 0 {
		// Use highest confidence ML result
		bestMLResult := mlResults[0]
		if bestMLResult.Confidence > 0.7 { // High confidence threshold
			// Boost threat level if ML is confident
			mlThreatBoost := int(bestMLResult.Probability * 5) // Scale to 0-5
			result.ThreatLevel = int(math.Max(float64(result.ThreatLevel), float64(mlThreatBoost)))
			
			// Add ML insights to metadata
			result.Metadata["ml_classification"] = map[string]interface{}{
				"threat_type": bestMLResult.ThreatType,
				"confidence":  bestMLResult.Confidence,
				"probability": bestMLResult.Probability,
			}
			
			// Add ML-specific recommendations
			if bestMLResult.Confidence > 0.8 {
				result.Recommendations = append(result.Recommendations, 
					fmt.Sprintf("ML model detected %s with %.1f%% confidence", 
						bestMLResult.ThreatType, bestMLResult.Confidence*100))
			}
		}
		result.Metadata["ml_results"] = mlResults
	}

	// Update device threat level
	device.ThreatLevel = result.ThreatLevel

	return result, nil
}

// evaluateThreatProfile checks if a device matches a threat profile
func (ie *IntelligenceEngine) evaluateThreatProfile(device *models.Device, profile *ThreatProfile) (bool, float64) {
	matchCount := 0
	totalWeight := 0.0
	matchWeight := 0.0

	for _, indicator := range profile.Indicators {
		totalWeight += indicator.Weight
		if ie.evaluateIndicator(device, &indicator) {
			matchCount++
			matchWeight += indicator.Weight
		}
	}

	if totalWeight == 0 {
		return false, 0
	}

	confidence := matchWeight / totalWeight
	threshold := 0.6 // 60% match required

	return confidence >= threshold, confidence
}

// evaluateIndicator checks if a device matches a specific threat indicator
func (ie *IntelligenceEngine) evaluateIndicator(device *models.Device, indicator *ThreatIndicator) bool {
	var fieldValue string
	var numValue float64

	// Extract field value from device
	switch indicator.Field {
	case "signal_level":
		numValue = float64(device.SignalLevel)
	case "name", "ssid":
		fieldValue = strings.ToLower(device.Name)
	case "manufacturer":
		fieldValue = strings.ToLower(device.Manufacturer)
	case "type":
		fieldValue = device.Type
	case "encryption":
		fieldValue = strings.ToLower(device.Encryption)
	case "seen_count":
		numValue = float64(device.SeenCount)
	case "threat_level":
		numValue = float64(device.ThreatLevel)
	default:
		return false
	}

	// Evaluate based on operator
	switch indicator.Operator {
	case "equals":
		return fieldValue == strings.ToLower(indicator.Value)
	case "contains":
		return strings.Contains(fieldValue, strings.ToLower(indicator.Value))
	case "not_contains":
		return !strings.Contains(fieldValue, strings.ToLower(indicator.Value))
	case "greater_than":
		threshold := parseFloat(indicator.Value)
		return numValue > threshold
	case "less_than":
		threshold := parseFloat(indicator.Value)
		return numValue < threshold
	case "regex":
		// TODO: Implement regex matching
		return false
	case "in_list":
		values := strings.Split(strings.ToLower(indicator.Value), ",")
		for _, v := range values {
			if strings.TrimSpace(v) == fieldValue {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// evaluateBehaviorRules applies behavior rules to analyze device behavior
func (ie *IntelligenceEngine) evaluateBehaviorRules(device *models.Device) (int, []string) {
	maxThreat := 0
	indicators := make([]string, 0)

	for _, rule := range ie.behaviorRules {
		if !rule.Enabled {
			continue
		}

		if ie.evaluateRule(device, rule) {
			if rule.Severity > maxThreat {
				maxThreat = rule.Severity
			}
			indicators = append(indicators, rule.Description)
		}
	}

	return maxThreat, indicators
}

// evaluateRule checks if a device triggers a behavior rule
func (ie *IntelligenceEngine) evaluateRule(device *models.Device, rule *BehaviorRule) bool {
	results := make([]bool, len(rule.Conditions))

	for i, condition := range rule.Conditions {
		results[i] = ie.evaluateCondition(device, &condition)
	}

	// Simple AND logic for now (can be extended for complex logic)
	for _, result := range results {
		if !result {
			return false
		}
	}

	return true
}

// evaluateCondition checks if a device meets a rule condition
func (ie *IntelligenceEngine) evaluateCondition(device *models.Device, condition *RuleCondition) bool {
	// Similar to evaluateIndicator but for rule conditions
	// Implementation would be similar to evaluateIndicator
	return false // Placeholder
}

// findThreatCorrelations looks for correlations between devices
func (ie *IntelligenceEngine) findThreatCorrelations(device *models.Device) []*ThreatCorrelation {
	correlations := make([]*ThreatCorrelation, 0)

	// Look for devices with similar characteristics
	// Check for temporal correlations
	// Analyze spatial correlations (if location data available)
	// Check for behavioral patterns

	return correlations
}

// generateRecommendations creates actionable recommendations based on analysis
func (ie *IntelligenceEngine) generateRecommendations(result *ThreatAnalysisResult) []string {
	recommendations := make([]string, 0)

	if result.ThreatLevel >= 7 {
		recommendations = append(recommendations, "IMMEDIATE ACTION: High threat detected - consider leaving the area")
		recommendations = append(recommendations, "Document all evidence and consider reporting to authorities")
	} else if result.ThreatLevel >= 5 {
		recommendations = append(recommendations, "Monitor device closely for continued presence")
		recommendations = append(recommendations, "Consider changing location if threat persists")
	} else if result.ThreatLevel >= 3 {
		recommendations = append(recommendations, "Continue passive monitoring")
		recommendations = append(recommendations, "Review device whitelist settings")
	}

	// Type-specific recommendations
	for _, threatType := range result.ThreatTypes {
		switch threatType {
		case "surveillance":
			recommendations = append(recommendations, "Check for visual surveillance equipment")
			recommendations = append(recommendations, "Disable unnecessary wireless interfaces")
		case "tracking":
			recommendations = append(recommendations, "Check personal belongings for tracking devices")
			recommendations = append(recommendations, "Enable location randomization if available")
		case "rogue_ap":
			recommendations = append(recommendations, "Avoid connecting to unknown WiFi networks")
			recommendations = append(recommendations, "Verify network credentials with venue staff")
		case "imsi_catcher":
			recommendations = append(recommendations, "Monitor for forced 2G connections")
			recommendations = append(recommendations, "Consider using airplane mode temporarily")
		}
	}

	return recommendations
}

// loadBuiltinThreatProfiles loads predefined threat profiles
func (ie *IntelligenceEngine) loadBuiltinThreatProfiles() error {
	// Hidden Camera WiFi Profile
	hiddenCameraProfile := &ThreatProfile{
		ID:       "hidden_camera_wifi",
		Name:     "Hidden Camera WiFi",
		Type:     "surveillance",
		Severity: 8,
		Indicators: []ThreatIndicator{
			{
				Type:        "network",
				Field:       "name",
				Operator:    "contains",
				Value:       "camera,cam,spy,hidden,surveillance,monitor",
				Weight:      0.9,
				Description: "Suspicious SSID indicating camera device",
			},
			{
				Type:        "signal",
				Field:       "signal_level",
				Operator:    "greater_than",
				Value:       "-40",
				Weight:      0.7,
				Description: "Very strong signal suggesting close proximity",
			},
			{
				Type:        "network",
				Field:       "encryption",
				Operator:    "equals",
				Value:       "open",
				Weight:      0.6,
				Description: "Open network potentially for easy access",
			},
		},
		LastUpdated: time.Now(),
	}

	// Bluetooth Tracker Profile
	bluetoothTrackerProfile := &ThreatProfile{
		ID:       "bluetooth_tracker",
		Name:     "Bluetooth Tracker",
		Type:     "tracking",
		Severity: 6,
		Indicators: []ThreatIndicator{
			{
				Type:        "device",
				Field:       "type",
				Operator:    "equals",
				Value:       "bluetooth",
				Weight:      1.0,
				Description: "Bluetooth device type",
			},
			{
				Type:        "signal",
				Field:       "signal_level",
				Operator:    "greater_than",
				Value:       "-50",
				Weight:      0.8,
				Description: "Strong signal indicating proximity",
			},
			{
				Type:        "behavior",
				Field:       "seen_count",
				Operator:    "greater_than",
				Value:       "5",
				Weight:      0.7,
				Description: "Persistent presence indicating tracking",
			},
		},
		LastUpdated: time.Now(),
	}

	// IMSI Catcher Profile
	imsiCatcherProfile := &ThreatProfile{
		ID:       "imsi_catcher",
		Name:     "IMSI Catcher",
		Type:     "imsi_catcher",
		Severity: 9,
		Indicators: []ThreatIndicator{
			{
				Type:        "device",
				Field:       "type",
				Operator:    "equals",
				Value:       "cellular",
				Weight:      1.0,
				Description: "Cellular device type",
			},
			{
				Type:        "signal",
				Field:       "signal_level",
				Operator:    "greater_than",
				Value:       "-50",
				Weight:      0.9,
				Description: "Unusually strong cellular signal",
			},
			{
				Type:        "network",
				Field:       "manufacturer",
				Operator:    "contains",
				Value:       "unknown,test,debug",
				Weight:      0.8,
				Description: "Suspicious operator name",
			},
		},
		LastUpdated: time.Now(),
	}

	// Store profiles
	ie.threatProfiles[hiddenCameraProfile.ID] = hiddenCameraProfile
	ie.threatProfiles[bluetoothTrackerProfile.ID] = bluetoothTrackerProfile
	ie.threatProfiles[imsiCatcherProfile.ID] = imsiCatcherProfile

	return nil
}

// loadBehaviorRules loads predefined behavior rules
func (ie *IntelligenceEngine) loadBehaviorRules() error {
	// Rapid appearance/disappearance rule
	rapidChangeRule := &BehaviorRule{
		ID:          "rapid_device_changes",
		Name:        "Rapid Device Changes",
		Description: "Device appearing and disappearing rapidly",
		Conditions: []RuleCondition{
			{
				Field:    "seen_count",
				Operator: "less_than",
				Value:    3,
				Logic:    "AND",
			},
			{
				Field:    "signal_level",
				Operator: "greater_than",
				Value:    -60,
				Logic:    "AND",
			},
		},
		Action:   "alert",
		Severity: 5,
		Enabled:  true,
	}

	ie.behaviorRules = append(ie.behaviorRules, rapidChangeRule)

	return nil
}

// Helper functions
func parseFloat(s string) float64 {
	// Simple float parsing - would be more robust in production
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
}

// ProcessContinuousAnalysis performs ongoing analysis of all devices
func (ie *IntelligenceEngine) ProcessContinuousAnalysis(ctx context.Context) error {
	ticker := time.NewTicker(ie.config.Core.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := ie.runContinuousAnalysis(); err != nil {
				fmt.Printf("Continuous analysis error: %v\n", err)
			}
		}
	}
}

// runContinuousAnalysis performs analysis on recent devices
func (ie *IntelligenceEngine) runContinuousAnalysis() error {
	// Get recent devices
	filter := &models.DeviceFilter{
		Since: time.Now().Add(-ie.config.Core.ScanInterval * 2),
		Limit: 100,
	}

	devices, err := ie.db.GetDevices(filter)
	if err != nil {
		return fmt.Errorf("failed to get recent devices: %w", err)
	}

	// Analyze each device
	for _, device := range devices {
		result, err := ie.AnalyzeDevice(&device)
		if err != nil {
			fmt.Printf("Analysis error for device %s: %v\n", device.ID, err)
			continue
		}

		// Generate alerts if needed
		if result.ThreatLevel >= ie.config.Notifications.Alerts.ThreatLevel {
			ie.alertManager.ProcessThreatAlert(&device, result)
		}
	}

	return nil
}
