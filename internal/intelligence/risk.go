package intelligence

import (
	"math"
	"time"

	"github.com/null/emily/internal/models"
)

// RiskCalculator provides comprehensive risk assessment capabilities
type RiskCalculator struct {
	riskFactors   []RiskFactor
	riskWeights   map[string]float64
	riskThresholds map[string]float64
}

// RiskFactor represents a factor that contributes to overall risk
type RiskFactor struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Category    string  `json:"category"` // technical, behavioral, contextual, temporal
	Description string  `json:"description"`
	Weight      float64 `json:"weight"`
	MaxScore    float64 `json:"max_score"`
	MinScore    float64 `json:"min_score"`
	Enabled     bool    `json:"enabled"`
}

// RiskAssessment represents a comprehensive risk assessment
type RiskAssessment struct {
	DeviceID           string                 `json:"device_id"`
	OverallRiskScore   float64                `json:"overall_risk_score"`
	RiskLevel          string                 `json:"risk_level"` // low, medium, high, critical
	Confidence         float64                `json:"confidence"`
	FactorScores       map[string]float64     `json:"factor_scores"`
	CategoryScores     map[string]float64     `json:"category_scores"`
	RiskIndicators     []string               `json:"risk_indicators"`
	Recommendations    []string               `json:"recommendations"`
	Metadata           map[string]interface{} `json:"metadata"`
	CalculatedAt       time.Time              `json:"calculated_at"`
	ValidUntil         time.Time              `json:"valid_until"`
}

// RiskContext provides context for risk calculation
type RiskContext struct {
	Environment     string                 `json:"environment"` // office, public, home, transport
	TimeOfDay       string                 `json:"time_of_day"` // morning, afternoon, evening, night
	DayOfWeek       string                 `json:"day_of_week"`
	LocationType    string                 `json:"location_type"`
	UserActivity    string                 `json:"user_activity"`
	SecurityLevel   string                 `json:"security_level"`
	ThreatLevel     int                    `json:"threat_level"`
	AdditionalData  map[string]interface{} `json:"additional_data"`
}

// NewRiskCalculator creates a new risk calculator
func NewRiskCalculator() *RiskCalculator {
	rc := &RiskCalculator{
		riskFactors:    make([]RiskFactor, 0),
		riskWeights:    make(map[string]float64),
		riskThresholds: make(map[string]float64),
	}
	
	// Load built-in risk factors and configure defaults
	rc.loadBuiltinRiskFactors()
	rc.configureRiskThresholds()
	
	return rc
}

// CalculateRisk performs comprehensive risk assessment
func (rc *RiskCalculator) CalculateRisk(device *models.Device, threatResult *ThreatAnalysisResult) *RiskAssessment {
	assessment := &RiskAssessment{
		DeviceID:        device.ID,
		FactorScores:    make(map[string]float64),
		CategoryScores:  make(map[string]float64),
		RiskIndicators:  make([]string, 0),
		Recommendations: make([]string, 0),
		Metadata:        make(map[string]interface{}),
		CalculatedAt:    time.Now(),
		ValidUntil:      time.Now().Add(30 * time.Minute), // Risk assessment valid for 30 minutes
	}

	// Create risk context
	context := rc.createRiskContext(device)
	
	// Calculate factor scores
	totalScore := 0.0
	totalWeight := 0.0
	categoryTotals := make(map[string]float64)
	categoryWeights := make(map[string]float64)

	for _, factor := range rc.riskFactors {
		if !factor.Enabled {
			continue
		}

		score := rc.calculateFactorScore(device, threatResult, &factor, context)
		weightedScore := score * factor.Weight
		
		assessment.FactorScores[factor.ID] = score
		totalScore += weightedScore
		totalWeight += factor.Weight
		
		// Aggregate by category
		categoryTotals[factor.Category] += weightedScore
		categoryWeights[factor.Category] += factor.Weight
		
		// Add risk indicators for high-scoring factors
		if score > 0.7 {
			assessment.RiskIndicators = append(assessment.RiskIndicators, factor.Description)
		}
	}

	// Calculate category scores
	for category, total := range categoryTotals {
		if categoryWeights[category] > 0 {
			assessment.CategoryScores[category] = total / categoryWeights[category]
		}
	}

	// Calculate overall risk score
	if totalWeight > 0 {
		assessment.OverallRiskScore = totalScore / totalWeight
	}

	// Incorporate threat analysis results
	assessment.OverallRiskScore = rc.incorporateThreatAnalysis(assessment.OverallRiskScore, threatResult)
	
	// Apply contextual adjustments
	assessment.OverallRiskScore = rc.applyContextualAdjustments(assessment.OverallRiskScore, context)
	
	// Determine risk level
	assessment.RiskLevel = rc.determineRiskLevel(assessment.OverallRiskScore)
	
	// Calculate confidence
	assessment.Confidence = rc.calculateConfidence(device, threatResult)
	
	// Generate recommendations
	assessment.Recommendations = rc.generateRiskRecommendations(assessment, context)
	
	// Add metadata
	assessment.Metadata["factor_count"] = len(rc.riskFactors)
	assessment.Metadata["context"] = context
	assessment.Metadata["calculation_method"] = "weighted_average"
	
	return assessment
}

// calculateFactorScore calculates the score for a specific risk factor
func (rc *RiskCalculator) calculateFactorScore(device *models.Device, threatResult *ThreatAnalysisResult, factor *RiskFactor, context *RiskContext) float64 {
	switch factor.ID {
	case "signal_strength":
		return rc.calculateSignalStrengthRisk(device)
	case "device_persistence":
		return rc.calculatePersistenceRisk(device)
	case "threat_indicators":
		return rc.calculateThreatIndicatorRisk(threatResult)
	case "device_behavior":
		return rc.calculateBehaviorRisk(device)
	case "encryption_weakness":
		return rc.calculateEncryptionRisk(device)
	case "manufacturer_suspicion":
		return rc.calculateManufacturerRisk(device)
	case "temporal_anomaly":
		return rc.calculateTemporalRisk(device, context)
	case "contextual_risk":
		return rc.calculateContextualRisk(device, context)
	case "correlation_risk":
		return rc.calculateCorrelationRisk(threatResult)
	case "pattern_risk":
		return rc.calculatePatternRisk(threatResult)
	default:
		return 0.0
	}
}

// Specific risk calculation functions

func (rc *RiskCalculator) calculateSignalStrengthRisk(device *models.Device) float64 {
	// Strong signals in unexpected contexts can indicate proximity threats
	signalLevel := float64(device.SignalLevel)
	
	// Convert to positive scale (stronger signal = higher potential risk in some contexts)
	if signalLevel > -30 {
		return 0.9 // Very strong signal - potential close-range threat
	} else if signalLevel > -50 {
		return 0.6 // Strong signal - moderate risk
	} else if signalLevel > -70 {
		return 0.3 // Normal signal - low risk
	}
	
	return 0.1 // Weak signal - minimal risk
}

func (rc *RiskCalculator) calculatePersistenceRisk(device *models.Device) float64 {
	// Devices that persist for long periods may indicate surveillance
	seenCount := float64(device.SeenCount)
	timeSinceFirst := time.Since(device.FirstSeen).Hours()
	
	persistenceScore := math.Min(seenCount/50.0, 1.0) // Normalize to 0-1
	timeScore := math.Min(timeSinceFirst/24.0, 1.0)   // Normalize based on 24 hours
	
	return (persistenceScore + timeScore) / 2.0
}

func (rc *RiskCalculator) calculateThreatIndicatorRisk(threatResult *ThreatAnalysisResult) float64 {
	if threatResult == nil {
		return 0.0
	}
	
	// Convert threat level to 0-1 scale
	threatScore := float64(threatResult.ThreatLevel) / 10.0
	confidenceScore := threatResult.Confidence
	
	return (threatScore + confidenceScore) / 2.0
}

func (rc *RiskCalculator) calculateBehaviorRisk(device *models.Device) float64 {
	// Analyze device behavior patterns
	behaviorScore := 0.0
	
	// Rapid appearance/disappearance
	if device.SeenCount < 5 && device.SignalLevel > -60 {
		behaviorScore += 0.3
	}
	
	// Unusual naming patterns
	if rc.hasSuspiciousName(device.Name) {
		behaviorScore += 0.4
	}
	
	// Type-specific behavior analysis
	switch device.Type {
	case "bluetooth":
		// Bluetooth devices that appear frequently might be tracking
		if device.SeenCount > 15 {
			behaviorScore += 0.3
		}
	case "wifi":
		// Hidden SSIDs can be suspicious
		if device.Name == "" || device.Name == "Hidden Network" {
			behaviorScore += 0.2
		}
	}
	
	return math.Min(behaviorScore, 1.0)
}

func (rc *RiskCalculator) calculateEncryptionRisk(device *models.Device) float64 {
	switch device.Encryption {
	case "open", "none", "":
		return 0.8 // Open networks are high risk
	case "wep":
		return 0.6 // WEP is weak encryption
	case "wpa":
		return 0.3 // WPA is moderate
	case "wpa2", "wpa3":
		return 0.1 // WPA2/3 are strong
	default:
		return 0.5 // Unknown encryption
	}
}

func (rc *RiskCalculator) calculateManufacturerRisk(device *models.Device) float64 {
	suspiciousManufacturers := []string{
		"unknown", "test", "debug", "surveillance", "monitor", "spy",
	}
	
	manufacturer := device.Manufacturer
	if manufacturer == "" {
		return 0.4 // Unknown manufacturer is moderately suspicious
	}
	
	for _, suspicious := range suspiciousManufacturers {
		if manufacturer == suspicious {
			return 0.9 // Highly suspicious manufacturer
		}
	}
	
	return 0.1 // Known legitimate manufacturer
}

func (rc *RiskCalculator) calculateTemporalRisk(device *models.Device, context *RiskContext) float64 {
	// Time-based risk factors
	riskScore := 0.0
	
	// Unusual hours (late night/early morning activity)
	hour := time.Now().Hour()
	if hour >= 23 || hour <= 5 {
		riskScore += 0.3
	}
	
	// Recent first appearance
	if time.Since(device.FirstSeen) < time.Hour {
		riskScore += 0.2
	}
	
	// Rapid frequency increase
	timeDiff := time.Since(device.FirstSeen).Hours()
	if timeDiff > 0 {
		frequency := float64(device.SeenCount) / timeDiff
		if frequency > 10 { // More than 10 detections per hour
			riskScore += 0.4
		}
	}
	
	return math.Min(riskScore, 1.0)
}

func (rc *RiskCalculator) calculateContextualRisk(device *models.Device, context *RiskContext) float64 {
	// Context-based risk assessment
	baseRisk := 0.0
	
	// Environment-specific risks
	switch context.Environment {
	case "public":
		baseRisk += 0.3 // Higher risk in public spaces
	case "transport":
		baseRisk += 0.4 // Higher risk in transport
	case "office":
		baseRisk += 0.1 // Lower risk in controlled environments
	case "home":
		baseRisk += 0.2 // Moderate risk at home
	}
	
	// Activity-specific risks
	switch context.UserActivity {
	case "meeting":
		baseRisk += 0.3 // Higher risk during sensitive activities
	case "travel":
		baseRisk += 0.4 // Higher risk while traveling
	case "work":
		baseRisk += 0.1 // Lower risk during routine work
	}
	
	return math.Min(baseRisk, 1.0)
}

func (rc *RiskCalculator) calculateCorrelationRisk(threatResult *ThreatAnalysisResult) float64 {
	if threatResult == nil || len(threatResult.Correlations) == 0 {
		return 0.0
	}
	
	// Risk increases with number of correlations
	correlationCount := float64(len(threatResult.Correlations))
	return math.Min(correlationCount/5.0, 1.0) // Normalize based on 5 correlations = max risk
}

func (rc *RiskCalculator) calculatePatternRisk(threatResult *ThreatAnalysisResult) float64 {
	if threatResult == nil {
		return 0.0
	}
	
	// Extract pattern information from metadata
	if patterns, ok := threatResult.Metadata["patterns"]; ok {
		if patternResult, ok := patterns.(*PatternAnalysisResult); ok {
			return patternResult.RiskScore
		}
	}
	
	return 0.0
}

// Helper functions

func (rc *RiskCalculator) hasSuspiciousName(name string) bool {
	suspiciousKeywords := []string{
		"camera", "spy", "surveillance", "monitor", "track", "hidden",
		"test", "debug", "hack", "exploit", "backdoor",
	}
	
	lowerName := name
	for _, keyword := range suspiciousKeywords {
		if lowerName == keyword {
			return true
		}
	}
	
	return false
}

func (rc *RiskCalculator) incorporateThreatAnalysis(baseScore float64, threatResult *ThreatAnalysisResult) float64 {
	if threatResult == nil {
		return baseScore
	}
	
	// Weight the base score with threat analysis
	threatScore := float64(threatResult.ThreatLevel) / 10.0
	confidence := threatResult.Confidence
	
	// Combine scores with confidence weighting
	combinedScore := (baseScore + threatScore*confidence) / (1.0 + confidence)
	
	return math.Min(combinedScore, 1.0)
}

func (rc *RiskCalculator) applyContextualAdjustments(score float64, context *RiskContext) float64 {
	adjustedScore := score
	
	// Apply environment multipliers
	switch context.Environment {
	case "public":
		adjustedScore *= 1.2 // Increase risk in public
	case "transport":
		adjustedScore *= 1.3 // Higher risk in transport
	case "home":
		adjustedScore *= 0.8 // Lower risk at home
	case "office":
		adjustedScore *= 0.9 // Slightly lower risk in office
	}
	
	// Apply time-of-day adjustments
	hour := time.Now().Hour()
	if hour >= 22 || hour <= 6 {
		adjustedScore *= 1.1 // Slight increase for unusual hours
	}
	
	return math.Min(adjustedScore, 1.0)
}

func (rc *RiskCalculator) determineRiskLevel(score float64) string {
	if score >= 0.8 {
		return "critical"
	} else if score >= 0.6 {
		return "high"
	} else if score >= 0.4 {
		return "medium"
	} else {
		return "low"
	}
}

func (rc *RiskCalculator) calculateConfidence(device *models.Device, threatResult *ThreatAnalysisResult) float64 {
	confidence := 0.5 // Base confidence
	
	// Increase confidence with more data points
	if device.SeenCount > 10 {
		confidence += 0.2
	}
	if device.SeenCount > 20 {
		confidence += 0.1
	}
	
	// Increase confidence with threat analysis
	if threatResult != nil && threatResult.Confidence > 0 {
		confidence = (confidence + threatResult.Confidence) / 2.0
	}
	
	// Increase confidence with longer observation time
	observationHours := time.Since(device.FirstSeen).Hours()
	if observationHours > 1 {
		confidence += 0.1
	}
	if observationHours > 6 {
		confidence += 0.1
	}
	
	return math.Min(confidence, 1.0)
}

func (rc *RiskCalculator) generateRiskRecommendations(assessment *RiskAssessment, context *RiskContext) []string {
	recommendations := make([]string, 0)
	
	// Critical risk recommendations
	if assessment.RiskLevel == "critical" {
		recommendations = append(recommendations, "CRITICAL: Immediate action required - consider leaving area")
		recommendations = append(recommendations, "Document all evidence and consider reporting to authorities")
		recommendations = append(recommendations, "Disable all unnecessary wireless interfaces")
	}
	
	// High risk recommendations
	if assessment.RiskLevel == "high" {
		recommendations = append(recommendations, "HIGH RISK: Increase vigilance and monitoring")
		recommendations = append(recommendations, "Consider changing location if threat persists")
		recommendations = append(recommendations, "Review and tighten security settings")
	}
	
	// Medium risk recommendations
	if assessment.RiskLevel == "medium" {
		recommendations = append(recommendations, "MEDIUM RISK: Continue monitoring with caution")
		recommendations = append(recommendations, "Review device whitelist settings")
	}
	
	// Factor-specific recommendations
	for factor, score := range assessment.FactorScores {
		if score > 0.7 {
			switch factor {
			case "signal_strength":
				recommendations = append(recommendations, "Strong signal detected - check for nearby unknown devices")
			case "device_persistence":
				recommendations = append(recommendations, "Persistent device detected - monitor for tracking behavior")
			case "encryption_weakness":
				recommendations = append(recommendations, "Weak encryption detected - avoid connecting to this network")
			case "temporal_anomaly":
				recommendations = append(recommendations, "Unusual timing pattern detected - increase awareness")
			}
		}
	}
	
	// Context-specific recommendations
	switch context.Environment {
	case "public":
		recommendations = append(recommendations, "In public area - maintain higher security awareness")
	case "transport":
		recommendations = append(recommendations, "In transit - be aware of mobile surveillance threats")
	}
	
	return recommendations
}

func (rc *RiskCalculator) createRiskContext(device *models.Device) *RiskContext {
	now := time.Now()
	
	context := &RiskContext{
		Environment:    "unknown", // Would be determined by user input or location services
		TimeOfDay:      rc.getTimeOfDay(now),
		DayOfWeek:      now.Weekday().String(),
		LocationType:   "unknown",
		UserActivity:   "unknown",
		SecurityLevel:  "normal",
		ThreatLevel:    device.ThreatLevel,
		AdditionalData: make(map[string]interface{}),
	}
	
	return context
}

func (rc *RiskCalculator) getTimeOfDay(t time.Time) string {
	hour := t.Hour()
	
	if hour >= 6 && hour < 12 {
		return "morning"
	} else if hour >= 12 && hour < 18 {
		return "afternoon"
	} else if hour >= 18 && hour < 22 {
		return "evening"
	} else {
		return "night"
	}
}

func (rc *RiskCalculator) loadBuiltinRiskFactors() {
	factors := []RiskFactor{
		{
			ID:          "signal_strength",
			Name:        "Signal Strength Risk",
			Category:    "technical",
			Description: "Risk based on signal strength patterns",
			Weight:      0.8,
			MaxScore:    1.0,
			MinScore:    0.0,
			Enabled:     true,
		},
		{
			ID:          "device_persistence",
			Name:        "Device Persistence",
			Category:    "behavioral",
			Description: "Risk from persistent device presence",
			Weight:      0.9,
			MaxScore:    1.0,
			MinScore:    0.0,
			Enabled:     true,
		},
		{
			ID:          "threat_indicators",
			Name:        "Threat Indicators",
			Category:    "technical",
			Description: "Risk from detected threat indicators",
			Weight:      1.0,
			MaxScore:    1.0,
			MinScore:    0.0,
			Enabled:     true,
		},
		{
			ID:          "device_behavior",
			Name:        "Device Behavior",
			Category:    "behavioral",
			Description: "Risk from suspicious device behavior",
			Weight:      0.7,
			MaxScore:    1.0,
			MinScore:    0.0,
			Enabled:     true,
		},
		{
			ID:          "encryption_weakness",
			Name:        "Encryption Weakness",
			Category:    "technical",
			Description: "Risk from weak or missing encryption",
			Weight:      0.6,
			MaxScore:    1.0,
			MinScore:    0.0,
			Enabled:     true,
		},
		{
			ID:          "manufacturer_suspicion",
			Name:        "Manufacturer Suspicion",
			Category:    "technical",
			Description: "Risk from suspicious manufacturer information",
			Weight:      0.5,
			MaxScore:    1.0,
			MinScore:    0.0,
			Enabled:     true,
		},
		{
			ID:          "temporal_anomaly",
			Name:        "Temporal Anomaly",
			Category:    "temporal",
			Description: "Risk from unusual timing patterns",
			Weight:      0.6,
			MaxScore:    1.0,
			MinScore:    0.0,
			Enabled:     true,
		},
		{
			ID:          "contextual_risk",
			Name:        "Contextual Risk",
			Category:    "contextual",
			Description: "Risk based on environmental context",
			Weight:      0.4,
			MaxScore:    1.0,
			MinScore:    0.0,
			Enabled:     true,
		},
		{
			ID:          "correlation_risk",
			Name:        "Correlation Risk",
			Category:    "behavioral",
			Description: "Risk from correlated threat events",
			Weight:      0.8,
			MaxScore:    1.0,
			MinScore:    0.0,
			Enabled:     true,
		},
		{
			ID:          "pattern_risk",
			Name:        "Pattern Risk",
			Category:    "behavioral",
			Description: "Risk from detected behavioral patterns",
			Weight:      0.9,
			MaxScore:    1.0,
			MinScore:    0.0,
			Enabled:     true,
		},
	}
	
	rc.riskFactors = factors
}

func (rc *RiskCalculator) configureRiskThresholds() {
	rc.riskThresholds = map[string]float64{
		"low":      0.4,
		"medium":   0.6,
		"high":     0.8,
		"critical": 1.0,
	}
}

// GetRiskFactors returns all configured risk factors
func (rc *RiskCalculator) GetRiskFactors() []RiskFactor {
	return rc.riskFactors
}

// UpdateRiskFactor updates a specific risk factor
func (rc *RiskCalculator) UpdateRiskFactor(factorID string, weight float64, enabled bool) error {
	for i, factor := range rc.riskFactors {
		if factor.ID == factorID {
			rc.riskFactors[i].Weight = weight
			rc.riskFactors[i].Enabled = enabled
			return nil
		}
	}
	return nil // Factor not found, but don't error
}

// GetRiskStatistics returns statistics about risk calculations
func (rc *RiskCalculator) GetRiskStatistics() map[string]interface{} {
	stats := make(map[string]interface{})
	
	enabledCount := 0
	totalWeight := 0.0
	categoryCount := make(map[string]int)
	
	for _, factor := range rc.riskFactors {
		if factor.Enabled {
			enabledCount++
			totalWeight += factor.Weight
		}
		categoryCount[factor.Category]++
	}
	
	stats["total_factors"] = len(rc.riskFactors)
	stats["enabled_factors"] = enabledCount
	stats["total_weight"] = totalWeight
	stats["category_breakdown"] = categoryCount
	stats["thresholds"] = rc.riskThresholds
	
	return stats
}
