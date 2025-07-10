package intelligence

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/null/emily/internal/models"
)

// BehavioralAnalyzer provides advanced behavioral analysis and device fingerprinting
type BehavioralAnalyzer struct {
	profiles        map[string]*DeviceProfile
	locationCluster *LocationClusterAnalyzer
	fingerprinter   *DeviceFingerprinter
	correlator      *LocationCorrelator
	mutex           sync.RWMutex
	config          *BehavioralConfig
}

// BehavioralConfig configures behavioral analysis parameters
type BehavioralConfig struct {
	MinObservations       int           `json:"min_observations"`
	ClusterRadius         float64       `json:"cluster_radius"`
	TimeWindow            time.Duration `json:"time_window"`
	SuspiciousThreshold   float64       `json:"suspicious_threshold"`
	FollowingThreshold    float64       `json:"following_threshold"`
	LocationUpdateFreq    time.Duration `json:"location_update_freq"`
	EnableFingerprinting  bool          `json:"enable_fingerprinting"`
	EnableLocationCorr    bool          `json:"enable_location_correlation"`
}

// DeviceProfile represents comprehensive behavioral profile of a device
type DeviceProfile struct {
	DeviceID            string                 `json:"device_id"`
	FirstSeen           time.Time              `json:"first_seen"`
	LastSeen            time.Time              `json:"last_seen"`
	TotalObservations   int                    `json:"total_observations"`
	
	// Temporal patterns
	ActiveTimeSlots     map[int]int            `json:"active_time_slots"` // Hour -> count
	DayOfWeekPattern    map[time.Weekday]int   `json:"day_of_week_pattern"`
	AverageSessionTime  time.Duration          `json:"average_session_time"`
	SessionFrequency    float64                `json:"session_frequency"`
	
	// Spatial patterns
	LocationClusters    []*LocationCluster     `json:"location_clusters"`
	MovementPatterns    *MovementProfile       `json:"movement_patterns"`
	ProximityPatterns   *ProximityProfile      `json:"proximity_patterns"`
	
	// Signal patterns
	SignalProfile       *SignalProfile         `json:"signal_profile"`
	FrequencyPattern    map[int]int            `json:"frequency_pattern"`
	ChannelPreferences  map[int]int            `json:"channel_preferences"`
	
	// Behavioral indicators
	StealthMetrics      *StealthMetrics        `json:"stealth_metrics"`
	SurveillanceScore   float64                `json:"surveillance_score"`
	TrackingLikelihood  float64                `json:"tracking_likelihood"`
	FollowingBehavior   *FollowingAnalysis     `json:"following_behavior"`
	
	// Device fingerprint
	Fingerprint         *DeviceFingerprint     `json:"fingerprint"`
	FingerprintChanges  int                    `json:"fingerprint_changes"`
	
	// Risk assessment
	ThreatLevel         int                    `json:"threat_level"`
	ConfidenceScore     float64                `json:"confidence_score"`
	LastRiskUpdate      time.Time              `json:"last_risk_update"`
	RiskFactors         []string               `json:"risk_factors"`
	
	UpdatedAt           time.Time              `json:"updated_at"`
}

// LocationCluster represents a geographical cluster of observations
type LocationCluster struct {
	ID              string    `json:"id"`
	CenterLat       float64   `json:"center_lat"`
	CenterLng       float64   `json:"center_lng"`
	Radius          float64   `json:"radius"`
	Observations    int       `json:"observations"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	AverageDwell    float64   `json:"average_dwell_time"`
	Significance    float64   `json:"significance"`
	IsSuspicious    bool      `json:"is_suspicious"`
}

// MovementProfile analyzes movement and mobility patterns
type MovementProfile struct {
	TotalDistance       float64   `json:"total_distance"`
	AverageSpeed        float64   `json:"average_speed"`
	MaxSpeed            float64   `json:"max_speed"`
	DirectionChanges    int       `json:"direction_changes"`
	StationaryPeriods   int       `json:"stationary_periods"`
	MobilityScore       float64   `json:"mobility_score"`
	Predictability      float64   `json:"predictability"`
	RoutePatterns       []string  `json:"route_patterns"`
	LastMovement        time.Time `json:"last_movement"`
}

// ProximityProfile analyzes proximity to user and other devices
type ProximityProfile struct {
	MinDistance         float64              `json:"min_distance"`
	MaxDistance         float64              `json:"max_distance"`
	AverageDistance     float64              `json:"average_distance"`
	CloseProximityCount int                  `json:"close_proximity_count"`
	ProximityHistory    []ProximityEvent     `json:"proximity_history"`
	StalkerLikelihood   float64              `json:"stalker_likelihood"`
	LastProximityCheck  time.Time            `json:"last_proximity_check"`
}

// ProximityEvent represents a proximity detection event
type ProximityEvent struct {
	Timestamp      time.Time `json:"timestamp"`
	Distance       float64   `json:"distance"`
	SignalStrength int       `json:"signal_strength"`
	Duration       float64   `json:"duration"`
	Context        string    `json:"context"`
}

// SignalProfile analyzes signal characteristics and patterns
type SignalProfile struct {
	AverageStrength     float64            `json:"average_strength"`
	SignalVariance      float64            `json:"signal_variance"`
	PeakStrength        int                `json:"peak_strength"`
	MinStrength         int                `json:"min_strength"`
	RapidChanges        int                `json:"rapid_changes"`
	AnomalousReadings   int                `json:"anomalous_readings"`
	StrengthTrend       string             `json:"strength_trend"`
	PowerLevelPattern   map[string]int     `json:"power_level_pattern"`
	TransmissionPattern *TransmissionProfile `json:"transmission_pattern"`
	LastSignalUpdate    time.Time          `json:"last_signal_update"`
}

// TransmissionProfile analyzes transmission patterns
type TransmissionProfile struct {
	TransmissionBursts  int       `json:"transmission_bursts"`
	SilentPeriods       int       `json:"silent_periods"`
	DataPattern         string    `json:"data_pattern"`
	BeaconInterval      float64   `json:"beacon_interval"`
	DutyCycle           float64   `json:"duty_cycle"`
	LastTransmission    time.Time `json:"last_transmission"`
}

// StealthMetrics tracks stealth and evasion characteristics
type StealthMetrics struct {
	NameChanges         int       `json:"name_changes"`
	MACRandomization    bool      `json:"mac_randomization"`
	SignalObfuscation   bool      `json:"signal_obfuscation"`
	IntermittentMode    bool      `json:"intermittent_mode"`
	AntiDetection       []string  `json:"anti_detection_techniques"`
	StealthScore        float64   `json:"stealth_score"`
	EvasionAttempts     int       `json:"evasion_attempts"`
	LastStealthActivity time.Time `json:"last_stealth_activity"`
}

// FollowingAnalysis analyzes if device is following user movements
type FollowingAnalysis struct {
	CorrelationScore    float64   `json:"correlation_score"`
	TimeOffset          float64   `json:"time_offset"`
	DistanceMaintained  float64   `json:"distance_maintained"`
	FollowingDuration   float64   `json:"following_duration"`
	FollowingConfidence float64   `json:"following_confidence"`
	RouteCorrelation    float64   `json:"route_correlation"`
	BehaviorMatch       float64   `json:"behavior_match"`
	LastFollowingDetected time.Time `json:"last_following_detected"`
}

// DeviceFingerprint provides unique device identification
type DeviceFingerprint struct {
	PrimaryHash         string            `json:"primary_hash"`
	SecondaryHashes     []string          `json:"secondary_hashes"`
	HardwareSignature   string            `json:"hardware_signature"`
	BehaviorSignature   string            `json:"behavior_signature"`
	NetworkSignature    string            `json:"network_signature"`
	CreatedAt           time.Time         `json:"created_at"`
	LastUpdated         time.Time         `json:"last_updated"`
	ConfidenceLevel     float64           `json:"confidence_level"`
	Attributes          map[string]string `json:"attributes"`
}

// LocationClusterAnalyzer performs location clustering analysis
type LocationClusterAnalyzer struct {
	clusters        map[string][]*LocationCluster
	minPoints       int
	epsilon         float64
	timeWindow      time.Duration
}

// DeviceFingerprinter generates unique device fingerprints
type DeviceFingerprinter struct {
	enabled         bool
	fingerprintDB   map[string]*DeviceFingerprint
	hashFunction    func(*models.Device) string
}

// LocationCorrelator correlates device movements with user patterns
type LocationCorrelator struct {
	userMovements   []LocationEvent
	deviceMovements map[string][]LocationEvent
	correlationMap  map[string]float64
	updateInterval  time.Duration
	lastUpdate      time.Time
}

// LocationEvent represents a location event for correlation
type LocationEvent struct {
	DeviceID   string    `json:"device_id"`
	Timestamp  time.Time `json:"timestamp"`
	Latitude   float64   `json:"latitude"`
	Longitude  float64   `json:"longitude"`
	Accuracy   float64   `json:"accuracy"`
	EventType  string    `json:"event_type"`
	Context    string    `json:"context"`
}

// NewBehavioralAnalyzer creates a new behavioral analyzer
func NewBehavioralAnalyzer(config *BehavioralConfig) *BehavioralAnalyzer {
	if config == nil {
		config = DefaultBehavioralConfig()
	}

	analyzer := &BehavioralAnalyzer{
		profiles:        make(map[string]*DeviceProfile),
		locationCluster: NewLocationClusterAnalyzer(config.ClusterRadius),
		fingerprinter:   NewDeviceFingerprinter(config.EnableFingerprinting),
		correlator:      NewLocationCorrelator(config.LocationUpdateFreq),
		config:          config,
	}

	return analyzer
}

// DefaultBehavioralConfig returns default configuration
func DefaultBehavioralConfig() *BehavioralConfig {
	return &BehavioralConfig{
		MinObservations:      5,
		ClusterRadius:        100.0, // meters
		TimeWindow:           24 * time.Hour,
		SuspiciousThreshold:  0.7,
		FollowingThreshold:   0.8,
		LocationUpdateFreq:   5 * time.Minute,
		EnableFingerprinting: true,
		EnableLocationCorr:   true,
	}
}

// AnalyzeDevice performs comprehensive behavioral analysis on a device
func (ba *BehavioralAnalyzer) AnalyzeDevice(device *models.Device) (*DeviceProfile, error) {
	ba.mutex.Lock()
	defer ba.mutex.Unlock()

	profile, exists := ba.profiles[device.ID]
	if !exists {
		profile = ba.createNewProfile(device)
		ba.profiles[device.ID] = profile
	}

	// Update profile with new observation
	ba.updateProfile(profile, device)

	// Perform analysis only if we have enough observations
	if profile.TotalObservations >= ba.config.MinObservations {
		ba.analyzeTemporalPatterns(profile)
		ba.analyzeSpatialPatterns(profile)
		ba.analyzeSignalPatterns(profile, device)
		ba.analyzeStealthBehavior(profile, device)
		ba.analyzeFollowingBehavior(profile)
		ba.calculateThreatLevel(profile)
	}

	// Update fingerprint if enabled
	if ba.config.EnableFingerprinting {
		ba.updateFingerprint(profile, device)
	}

	profile.UpdatedAt = time.Now()
	return profile, nil
}

// createNewProfile creates a new device profile
func (ba *BehavioralAnalyzer) createNewProfile(device *models.Device) *DeviceProfile {
	now := time.Now()
	
	profile := &DeviceProfile{
		DeviceID:           device.ID,
		FirstSeen:          now,
		LastSeen:           now,
		TotalObservations:  0,
		ActiveTimeSlots:    make(map[int]int),
		DayOfWeekPattern:   make(map[time.Weekday]int),
		LocationClusters:   make([]*LocationCluster, 0),
		FrequencyPattern:   make(map[int]int),
		ChannelPreferences: make(map[int]int),
		RiskFactors:        make([]string, 0),
		MovementPatterns:   &MovementProfile{},
		ProximityPatterns:  &ProximityProfile{ProximityHistory: make([]ProximityEvent, 0)},
		SignalProfile:      &SignalProfile{PowerLevelPattern: make(map[string]int)},
		StealthMetrics:     &StealthMetrics{AntiDetection: make([]string, 0)},
		FollowingBehavior:  &FollowingAnalysis{},
		UpdatedAt:          now,
	}

	// Initialize fingerprint if enabled
	if ba.config.EnableFingerprinting {
		profile.Fingerprint = ba.fingerprinter.GenerateFingerprint(device)
	}

	return profile
}

// updateProfile updates profile with new device observation
func (ba *BehavioralAnalyzer) updateProfile(profile *DeviceProfile, device *models.Device) {
	now := time.Now()
	profile.LastSeen = now
	profile.TotalObservations++

	// Update temporal patterns
	hour := now.Hour()
	profile.ActiveTimeSlots[hour]++
	profile.DayOfWeekPattern[now.Weekday()]++

	// Update frequency and channel patterns
	if device.Frequency > 0 {
		freqBand := int(device.Frequency / 1000000) // Convert to MHz
		profile.FrequencyPattern[freqBand]++
	}
	if device.Channel > 0 {
		profile.ChannelPreferences[device.Channel]++
	}

	// Update signal profile
	ba.updateSignalProfile(profile.SignalProfile, device)
}

// updateSignalProfile updates signal analysis profile
func (ba *BehavioralAnalyzer) updateSignalProfile(signal *SignalProfile, device *models.Device) {
	signal.LastSignalUpdate = time.Now()
	
	// Update signal strength statistics
	if signal.PeakStrength == 0 || device.SignalLevel > signal.PeakStrength {
		signal.PeakStrength = device.SignalLevel
	}
	if signal.MinStrength == 0 || device.SignalLevel < signal.MinStrength {
		signal.MinStrength = device.SignalLevel
	}

	// Update power level pattern
	powerLevel := "low"
	if device.SignalLevel > -50 {
		powerLevel = "high"
	} else if device.SignalLevel > -70 {
		powerLevel = "medium"
	}
	signal.PowerLevelPattern[powerLevel]++

	// Detect rapid signal changes (would need historical data)
	// This is simplified for now
	if math.Abs(float64(device.SignalLevel-signal.PeakStrength)) > 20 {
		signal.RapidChanges++
	}
}

// analyzeTemporalPatterns analyzes temporal behavior patterns
func (ba *BehavioralAnalyzer) analyzeTemporalPatterns(profile *DeviceProfile) {
	// Calculate session frequency
	if profile.TotalObservations > 1 {
		totalTime := profile.LastSeen.Sub(profile.FirstSeen).Hours()
		if totalTime > 0 {
			profile.SessionFrequency = float64(profile.TotalObservations) / totalTime
		}
	}

	// Analyze time slot distribution for suspicious patterns
	maxActivity := 0
	for _, count := range profile.ActiveTimeSlots {
		if count > maxActivity {
			maxActivity = count
		}
	}

	// Check for unusual activity patterns (night time activity might be suspicious)
	nightActivity := profile.ActiveTimeSlots[0] + profile.ActiveTimeSlots[1] + 
					profile.ActiveTimeSlots[2] + profile.ActiveTimeSlots[3] + 
					profile.ActiveTimeSlots[4] + profile.ActiveTimeSlots[5]
	
	if float64(nightActivity)/float64(profile.TotalObservations) > 0.3 {
		profile.RiskFactors = append(profile.RiskFactors, "High night-time activity")
	}
}

// analyzeSpatialPatterns analyzes spatial behavior patterns
func (ba *BehavioralAnalyzer) analyzeSpatialPatterns(profile *DeviceProfile) {
	// This would analyze location clusters and movement patterns
	// For now, we'll create a placeholder implementation

	// Update mobility score based on signal strength variation
	signalVariation := float64(profile.SignalProfile.PeakStrength - profile.SignalProfile.MinStrength)
	if signalVariation > 30 {
		profile.MovementPatterns.MobilityScore = 0.8 // High mobility
	} else if signalVariation > 15 {
		profile.MovementPatterns.MobilityScore = 0.5 // Medium mobility
	} else {
		profile.MovementPatterns.MobilityScore = 0.2 // Low mobility (stationary)
	}

	// High mobility combined with frequent observations might indicate tracking
	if profile.MovementPatterns.MobilityScore > 0.6 && profile.SessionFrequency > 2.0 {
		profile.RiskFactors = append(profile.RiskFactors, "High mobility with frequent observations")
	}
}

// analyzeSignalPatterns analyzes signal-based patterns
func (ba *BehavioralAnalyzer) analyzeSignalPatterns(profile *DeviceProfile, device *models.Device) {
	signal := profile.SignalProfile

	// Calculate signal variance (simplified)
	signal.SignalVariance = float64(signal.PeakStrength - signal.MinStrength)

	// Detect anomalous signal strength
	if device.SignalLevel > -30 { // Very strong signal
		signal.AnomalousReadings++
		profile.RiskFactors = append(profile.RiskFactors, "Unusually strong signal")
	}

	// Analyze power patterns for surveillance indicators
	highPowerRatio := float64(signal.PowerLevelPattern["high"]) / float64(profile.TotalObservations)
	if highPowerRatio > 0.7 {
		profile.RiskFactors = append(profile.RiskFactors, "Consistently high power transmission")
	}
}

// analyzeStealthBehavior analyzes stealth and evasion behaviors
func (ba *BehavioralAnalyzer) analyzeStealthBehavior(profile *DeviceProfile, device *models.Device) {
	stealth := profile.StealthMetrics

	// Detect MAC randomization (simplified check)
	if len(device.MAC) > 0 && device.MAC[:2] == "02" {
		stealth.MACRandomization = true
		stealth.AntiDetection = append(stealth.AntiDetection, "MAC randomization")
	}

	// Detect intermittent mode (low observation frequency with gaps)
	if profile.SessionFrequency < 0.5 && profile.TotalObservations > 10 {
		stealth.IntermittentMode = true
		stealth.AntiDetection = append(stealth.AntiDetection, "Intermittent operation")
	}

	// Calculate stealth score
	stealthFactors := 0
	if stealth.MACRandomization {
		stealthFactors++
	}
	if stealth.IntermittentMode {
		stealthFactors++
	}
	if stealth.NameChanges > 2 {
		stealthFactors++
	}

	stealth.StealthScore = float64(stealthFactors) / 3.0 // Normalize to 0-1

	if stealth.StealthScore > 0.6 {
		profile.RiskFactors = append(profile.RiskFactors, "High stealth behavior")
	}
}

// analyzeFollowingBehavior analyzes following/tracking behavior
func (ba *BehavioralAnalyzer) analyzeFollowingBehavior(profile *DeviceProfile) {
	following := profile.FollowingBehavior

	// Simplified following detection based on consistency and frequency
	// In a real implementation, this would use location correlation
	
	// High frequency + consistent behavior might indicate following
	consistencyScore := 1.0 - (profile.SignalProfile.SignalVariance / 100.0)
	if consistencyScore < 0 {
		consistencyScore = 0
	}

	following.CorrelationScore = consistencyScore * profile.SessionFrequency / 10.0
	if following.CorrelationScore > 1.0 {
		following.CorrelationScore = 1.0
	}

	following.FollowingConfidence = following.CorrelationScore

	if following.FollowingConfidence > ba.config.FollowingThreshold {
		profile.RiskFactors = append(profile.RiskFactors, "Potential following behavior")
		following.LastFollowingDetected = time.Now()
	}
}

// calculateThreatLevel calculates overall threat level
func (ba *BehavioralAnalyzer) calculateThreatLevel(profile *DeviceProfile) {
	// Base threat level calculation
	threatScore := 0.0

	// Risk factors contribute to threat
	threatScore += float64(len(profile.RiskFactors)) * 0.15

	// Stealth behavior increases threat
	threatScore += profile.StealthMetrics.StealthScore * 0.3

	// Following behavior increases threat significantly
	threatScore += profile.FollowingBehavior.FollowingConfidence * 0.4

	// Signal anomalies increase threat
	if profile.SignalProfile.AnomalousReadings > 0 {
		threatScore += 0.2
	}

	// Normalize and convert to 1-10 scale
	if threatScore > 1.0 {
		threatScore = 1.0
	}

	profile.SurveillanceScore = threatScore
	profile.ThreatLevel = int(threatScore * 10)
	profile.ConfidenceScore = math.Min(1.0, float64(profile.TotalObservations)/float64(ba.config.MinObservations*2))
	profile.LastRiskUpdate = time.Now()
}

// updateFingerprint updates device fingerprint
func (ba *BehavioralAnalyzer) updateFingerprint(profile *DeviceProfile, device *models.Device) {
	newFingerprint := ba.fingerprinter.GenerateFingerprint(device)
	
	if profile.Fingerprint == nil {
		profile.Fingerprint = newFingerprint
	} else {
		// Check if fingerprint has changed significantly
		if profile.Fingerprint.PrimaryHash != newFingerprint.PrimaryHash {
			profile.FingerprintChanges++
			profile.Fingerprint = newFingerprint
			profile.RiskFactors = append(profile.RiskFactors, "Device fingerprint changed")
		}
	}
}

// GetDeviceProfile retrieves device profile
func (ba *BehavioralAnalyzer) GetDeviceProfile(deviceID string) (*DeviceProfile, bool) {
	ba.mutex.RLock()
	defer ba.mutex.RUnlock()
	
	profile, exists := ba.profiles[deviceID]
	return profile, exists
}

// GetHighRiskDevices returns devices with high threat levels
func (ba *BehavioralAnalyzer) GetHighRiskDevices(threshold int) []*DeviceProfile {
	ba.mutex.RLock()
	defer ba.mutex.RUnlock()

	highRisk := make([]*DeviceProfile, 0)
	for _, profile := range ba.profiles {
		if profile.ThreatLevel >= threshold {
			highRisk = append(highRisk, profile)
		}
	}

	// Sort by threat level (highest first)
	sort.Slice(highRisk, func(i, j int) bool {
		return highRisk[i].ThreatLevel > highRisk[j].ThreatLevel
	})

	return highRisk
}

// NewLocationClusterAnalyzer creates location cluster analyzer
func NewLocationClusterAnalyzer(epsilon float64) *LocationClusterAnalyzer {
	return &LocationClusterAnalyzer{
		clusters:   make(map[string][]*LocationCluster),
		minPoints:  3,
		epsilon:    epsilon,
		timeWindow: 24 * time.Hour,
	}
}

// NewDeviceFingerprinter creates device fingerprinter
func NewDeviceFingerprinter(enabled bool) *DeviceFingerprinter {
	return &DeviceFingerprinter{
		enabled:       enabled,
		fingerprintDB: make(map[string]*DeviceFingerprint),
		hashFunction:  defaultHashFunction,
	}
}

// GenerateFingerprint generates device fingerprint
func (df *DeviceFingerprinter) GenerateFingerprint(device *models.Device) *DeviceFingerprint {
	if !df.enabled {
		return nil
	}

	// Create primary hash from key device characteristics
	primaryHash := df.hashFunction(device)

	// Create secondary hashes for redundancy
	secondaryHashes := []string{
		fmt.Sprintf("%x", md5.Sum([]byte(device.Name+device.Type))),
		fmt.Sprintf("%x", md5.Sum([]byte(device.Manufacturer+device.Encryption))),
	}

	fingerprint := &DeviceFingerprint{
		PrimaryHash:       primaryHash,
		SecondaryHashes:   secondaryHashes,
		HardwareSignature: fmt.Sprintf("%s_%s", device.Manufacturer, device.Type),
		CreatedAt:         time.Now(),
		LastUpdated:       time.Now(),
		ConfidenceLevel:   0.8,
		Attributes: map[string]string{
			"type":         device.Type,
			"manufacturer": device.Manufacturer,
			"encryption":   device.Encryption,
		},
	}

	df.fingerprintDB[fingerprint.PrimaryHash] = fingerprint
	return fingerprint
}

// defaultHashFunction creates a hash from device characteristics
func defaultHashFunction(device *models.Device) string {
	data := fmt.Sprintf("%s:%s:%s:%d", device.Type, device.MAC, device.Manufacturer, device.Frequency)
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

// NewLocationCorrelator creates location correlator
func NewLocationCorrelator(updateInterval time.Duration) *LocationCorrelator {
	return &LocationCorrelator{
		userMovements:   make([]LocationEvent, 0),
		deviceMovements: make(map[string][]LocationEvent),
		correlationMap:  make(map[string]float64),
		updateInterval:  updateInterval,
		lastUpdate:      time.Now(),
	}
}

// GetAnalysisStatistics returns analysis statistics
func (ba *BehavioralAnalyzer) GetAnalysisStatistics() map[string]interface{} {
	ba.mutex.RLock()
	defer ba.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_profiles"] = len(ba.profiles)

	threatLevels := make(map[int]int)
	totalRiskFactors := 0
	highRiskCount := 0

	for _, profile := range ba.profiles {
		threatLevels[profile.ThreatLevel]++
		totalRiskFactors += len(profile.RiskFactors)
		if profile.ThreatLevel >= 7 {
			highRiskCount++
		}
	}

	stats["threat_level_distribution"] = threatLevels
	stats["average_risk_factors"] = float64(totalRiskFactors) / float64(len(ba.profiles))
	stats["high_risk_devices"] = highRiskCount
	stats["fingerprinting_enabled"] = ba.config.EnableFingerprinting
	stats["location_correlation_enabled"] = ba.config.EnableLocationCorr

	return stats
}
