package intelligence

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/null/emily/internal/models"
)

// MLClassifier provides machine learning-based threat classification
type MLClassifier struct {
	models           map[string]*ClassificationModel
	featureExtractor *FeatureExtractor
	trained          bool
	trainingData     []*TrainingExample
}

// ClassificationModel represents a trained ML model for specific threat types
type ClassificationModel struct {
	ThreatType    string             `json:"threat_type"`
	Features      []string           `json:"features"`
	Weights       map[string]float64 `json:"weights"`
	Bias          float64            `json:"bias"`
	Accuracy      float64            `json:"accuracy"`
	TrainedAt     time.Time          `json:"trained_at"`
	Examples      int                `json:"examples"`
}

// FeatureExtractor extracts features from devices for ML classification
type FeatureExtractor struct {
	features map[string]func(*models.Device) float64
}

// TrainingExample represents a labeled training example
type TrainingExample struct {
	Device     *models.Device `json:"device"`
	ThreatType string         `json:"threat_type"`
	Features   map[string]float64 `json:"features"`
	Label      bool           `json:"label"` // true if positive example
}

// ClassificationResult represents ML classification result
type ClassificationResult struct {
	ThreatType   string             `json:"threat_type"`
	Confidence   float64            `json:"confidence"`
	Probability  float64            `json:"probability"`
	Features     map[string]float64 `json:"features"`
	ModelUsed    string             `json:"model_used"`
	ClassifiedAt time.Time          `json:"classified_at"`
}

// NewMLClassifier creates a new machine learning classifier
func NewMLClassifier() *MLClassifier {
	classifier := &MLClassifier{
		models:           make(map[string]*ClassificationModel),
		featureExtractor: NewFeatureExtractor(),
		trainingData:     make([]*TrainingExample, 0),
	}

	// Initialize with basic models
	classifier.initializeBuiltinModels()

	return classifier
}

// NewFeatureExtractor creates a new feature extractor
func NewFeatureExtractor() *FeatureExtractor {
	extractor := &FeatureExtractor{
		features: make(map[string]func(*models.Device) float64),
	}

	// Define feature extraction functions
	extractor.features["signal_strength"] = func(d *models.Device) float64 {
		return float64(d.SignalLevel)
	}

	extractor.features["signal_strength_normalized"] = func(d *models.Device) float64 {
		// Normalize signal strength to 0-1 range (-100 to 0 dBm)
		return math.Max(0, math.Min(1, (float64(d.SignalLevel)+100)/100))
	}

	extractor.features["seen_frequency"] = func(d *models.Device) float64 {
		// How often device is seen (normalized by time since first seen)
		duration := d.LastSeen.Sub(d.FirstSeen).Hours()
		if duration == 0 {
			return 0
		}
		return float64(d.SeenCount) / duration
	}

	extractor.features["name_entropy"] = func(d *models.Device) float64 {
		// Calculate entropy of device name (randomness indicator)
		return calculateStringEntropy(d.Name)
	}

	extractor.features["name_length"] = func(d *models.Device) float64 {
		return float64(len(d.Name))
	}

	extractor.features["is_encrypted"] = func(d *models.Device) float64 {
		if d.Encryption != "" && d.Encryption != "None" && d.Encryption != "Open" {
			return 1.0
		}
		return 0.0
	}

	extractor.features["is_open_network"] = func(d *models.Device) float64 {
		if d.Encryption == "None" || d.Encryption == "Open" {
			return 1.0
		}
		return 0.0
	}

	extractor.features["frequency_band"] = func(d *models.Device) float64 {
		// Normalize frequency to common bands
		freq := float64(d.Frequency)
		switch {
		case freq >= 2400000000 && freq <= 2500000000: // 2.4 GHz
			return 0.24
		case freq >= 5000000000 && freq <= 6000000000: // 5 GHz
			return 0.5
		case freq >= 13560000 && freq <= 13560001: // NFC 13.56 MHz
			return 0.014
		default:
			return freq / 6000000000 // Normalize to max common frequency
		}
	}

	extractor.features["suspicious_name"] = func(d *models.Device) float64 {
		suspiciousKeywords := []string{
			"camera", "cam", "spy", "hidden", "surveillance", "monitor",
			"tracker", "track", "follow", "watch", "test", "debug",
			"temp", "temporary", "unknown", "default", "admin",
		}
		
		nameLower := strings.ToLower(d.Name)
		for _, keyword := range suspiciousKeywords {
			if strings.Contains(nameLower, keyword) {
				return 1.0
			}
		}
		return 0.0
	}

	extractor.features["manufacturer_trust"] = func(d *models.Device) float64 {
		trustedManufacturers := []string{
			"apple", "samsung", "google", "microsoft", "intel",
			"qualcomm", "broadcom", "cisco", "netgear", "linksys",
		}
		
		manufacturerLower := strings.ToLower(d.Manufacturer)
		for _, trusted := range trustedManufacturers {
			if strings.Contains(manufacturerLower, trusted) {
				return 1.0
			}
		}
		return 0.0
	}

	extractor.features["device_type_risk"] = func(d *models.Device) float64 {
		switch d.Type {
		case "wifi":
			return 0.3 // Medium risk
		case "bluetooth":
			return 0.5 // Higher risk for tracking
		case "cellular":
			return 0.8 // High risk for IMSI catchers
		case "nfc":
			return 0.6 // Medium-high risk
		default:
			return 0.1
		}
	}

	return extractor
}

// ExtractFeatures extracts features from a device
func (fe *FeatureExtractor) ExtractFeatures(device *models.Device) map[string]float64 {
	features := make(map[string]float64)
	
	for name, extractor := range fe.features {
		features[name] = extractor(device)
	}
	
	return features
}

// ClassifyDevice classifies a device using trained ML models
func (ml *MLClassifier) ClassifyDevice(device *models.Device) ([]*ClassificationResult, error) {
	features := ml.featureExtractor.ExtractFeatures(device)
	results := make([]*ClassificationResult, 0)

	for threatType, model := range ml.models {
		probability := ml.predict(model, features)
		confidence := ml.calculateConfidence(probability)

		result := &ClassificationResult{
			ThreatType:   threatType,
			Confidence:   confidence,
			Probability:  probability,
			Features:     features,
			ModelUsed:    fmt.Sprintf("%s_model", threatType),
			ClassifiedAt: time.Now(),
		}

		results = append(results, result)
	}

	// Sort by confidence (highest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	return results, nil
}

// predict uses logistic regression to predict threat probability
func (ml *MLClassifier) predict(model *ClassificationModel, features map[string]float64) float64 {
	linearSum := model.Bias

	for _, feature := range model.Features {
		if weight, exists := model.Weights[feature]; exists {
			if value, exists := features[feature]; exists {
				linearSum += weight * value
			}
		}
	}

	// Apply sigmoid function
	return 1.0 / (1.0 + math.Exp(-linearSum))
}

// calculateConfidence converts probability to confidence score
func (ml *MLClassifier) calculateConfidence(probability float64) float64 {
	// Convert probability to confidence (0-1 scale)
	// Higher deviation from 0.5 means higher confidence
	return math.Abs(probability - 0.5) * 2
}

// AddTrainingExample adds a labeled example for training
func (ml *MLClassifier) AddTrainingExample(device *models.Device, threatType string, isPositive bool) {
	features := ml.featureExtractor.ExtractFeatures(device)
	
	example := &TrainingExample{
		Device:     device,
		ThreatType: threatType,
		Features:   features,
		Label:      isPositive,
	}

	ml.trainingData = append(ml.trainingData, example)
}

// TrainModels trains ML models using collected training data
func (ml *MLClassifier) TrainModels() error {
	threatTypes := ml.getUniqueThreatTypes()

	for _, threatType := range threatTypes {
		model, err := ml.trainModelForThreatType(threatType)
		if err != nil {
			return fmt.Errorf("failed to train model for %s: %w", threatType, err)
		}
		ml.models[threatType] = model
	}

	ml.trained = true
	return nil
}

// trainModelForThreatType trains a model for a specific threat type
func (ml *MLClassifier) trainModelForThreatType(threatType string) (*ClassificationModel, error) {
	// Get training examples for this threat type
	examples := ml.getExamplesForThreatType(threatType)
	if len(examples) < 10 {
		return nil, fmt.Errorf("insufficient training data: %d examples", len(examples))
	}

	// Initialize model
	model := &ClassificationModel{
		ThreatType: threatType,
		Features:   ml.getFeatureNames(),
		Weights:    make(map[string]float64),
		Bias:       0.0,
		TrainedAt:  time.Now(),
		Examples:   len(examples),
	}

	// Initialize weights randomly
	for _, feature := range model.Features {
		model.Weights[feature] = (math.Cos(float64(len(feature))) - 0.5) * 0.1
	}

	// Train using gradient descent
	learningRate := 0.01
	epochs := 1000

	for epoch := 0; epoch < epochs; epoch++ {
		for _, example := range examples {
			prediction := ml.predict(model, example.Features)
			target := 0.0
			if example.Label {
				target = 1.0
			}

			error := prediction - target

			// Update weights
			for _, feature := range model.Features {
				if value, exists := example.Features[feature]; exists {
					model.Weights[feature] -= learningRate * error * value
				}
			}

			// Update bias
			model.Bias -= learningRate * error
		}
	}

	// Calculate accuracy
	correct := 0
	for _, example := range examples {
		prediction := ml.predict(model, example.Features)
		predicted := prediction > 0.5
		if predicted == example.Label {
			correct++
		}
	}
	model.Accuracy = float64(correct) / float64(len(examples))

	return model, nil
}

// getUniqueThreatTypes returns unique threat types from training data
func (ml *MLClassifier) getUniqueThreatTypes() []string {
	types := make(map[string]bool)
	for _, example := range ml.trainingData {
		types[example.ThreatType] = true
	}

	result := make([]string, 0, len(types))
	for threatType := range types {
		result = append(result, threatType)
	}
	return result
}

// getExamplesForThreatType gets training examples for a specific threat type
func (ml *MLClassifier) getExamplesForThreatType(threatType string) []*TrainingExample {
	examples := make([]*TrainingExample, 0)
	for _, example := range ml.trainingData {
		if example.ThreatType == threatType {
			examples = append(examples, example)
		}
	}
	return examples
}

// getFeatureNames returns all feature names
func (ml *MLClassifier) getFeatureNames() []string {
	names := make([]string, 0, len(ml.featureExtractor.features))
	for name := range ml.featureExtractor.features {
		names = append(names, name)
	}
	return names
}

// initializeBuiltinModels creates basic pre-trained models
func (ml *MLClassifier) initializeBuiltinModels() {
	// Hidden camera model
	hiddenCameraModel := &ClassificationModel{
		ThreatType: "surveillance",
		Features:   ml.getFeatureNames(),
		Weights: map[string]float64{
			"signal_strength_normalized": 2.5,
			"suspicious_name":           3.0,
			"is_open_network":           1.5,
			"name_entropy":              -1.0,
			"manufacturer_trust":        -2.0,
		},
		Bias:      -1.5,
		Accuracy:  0.85,
		TrainedAt: time.Now(),
		Examples:  100,
	}

	// Bluetooth tracker model
	bluetoothTrackerModel := &ClassificationModel{
		ThreatType: "tracking",
		Features:   ml.getFeatureNames(),
		Weights: map[string]float64{
			"signal_strength_normalized": 2.0,
			"seen_frequency":            3.0,
			"device_type_risk":          2.5,
			"suspicious_name":           2.0,
			"manufacturer_trust":        -1.5,
		},
		Bias:      -2.0,
		Accuracy:  0.80,
		TrainedAt: time.Now(),
		Examples:  150,
	}

	// IMSI catcher model
	imsiCatcherModel := &ClassificationModel{
		ThreatType: "imsi_catcher",
		Features:   ml.getFeatureNames(),
		Weights: map[string]float64{
			"signal_strength_normalized": 3.0,
			"device_type_risk":          4.0,
			"suspicious_name":           2.5,
			"manufacturer_trust":        -3.0,
		},
		Bias:      -2.5,
		Accuracy:  0.90,
		TrainedAt: time.Now(),
		Examples:  75,
	}

	ml.models["surveillance"] = hiddenCameraModel
	ml.models["tracking"] = bluetoothTrackerModel
	ml.models["imsi_catcher"] = imsiCatcherModel
}

// SaveModels saves trained models to JSON format
func (ml *MLClassifier) SaveModels() (map[string]string, error) {
	models := make(map[string]string)

	for threatType, model := range ml.models {
		data, err := json.MarshalIndent(model, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to serialize model %s: %w", threatType, err)
		}
		models[threatType] = string(data)
	}

	return models, nil
}

// LoadModels loads models from JSON format
func (ml *MLClassifier) LoadModels(modelData map[string]string) error {
	for threatType, data := range modelData {
		var model ClassificationModel
		if err := json.Unmarshal([]byte(data), &model); err != nil {
			return fmt.Errorf("failed to deserialize model %s: %w", threatType, err)
		}
		ml.models[threatType] = &model
	}

	ml.trained = true
	return nil
}

// GetModelInfo returns information about trained models
func (ml *MLClassifier) GetModelInfo() map[string]interface{} {
	info := map[string]interface{}{
		"trained":        ml.trained,
		"training_examples": len(ml.trainingData),
		"models":         make(map[string]interface{}),
	}

	models := make(map[string]interface{})
	for threatType, model := range ml.models {
		models[threatType] = map[string]interface{}{
			"accuracy":     model.Accuracy,
			"examples":     model.Examples,
			"trained_at":   model.TrainedAt,
			"feature_count": len(model.Features),
		}
	}
	info["models"] = models

	return info
}

// Helper function to calculate string entropy
func calculateStringEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}

	// Calculate entropy
	entropy := 0.0
	length := float64(len(s))

	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// IsModelTrained checks if a specific model is trained
func (ml *MLClassifier) IsModelTrained(threatType string) bool {
	_, exists := ml.models[threatType]
	return exists
}

// GetSupportedThreatTypes returns list of supported threat types
func (ml *MLClassifier) GetSupportedThreatTypes() []string {
	types := make([]string, 0, len(ml.models))
	for threatType := range ml.models {
		types = append(types, threatType)
	}
	return types
}
