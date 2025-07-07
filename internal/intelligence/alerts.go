package intelligence

import (
	"fmt"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/database"
	"github.com/null/emily/internal/models"
)

// AlertManager handles alert generation, processing, and notifications
type AlertManager struct {
	config *config.Config
	db     *database.Database
}

// NewAlertManager creates a new alert manager
func NewAlertManager(cfg *config.Config, db *database.Database) *AlertManager {
	return &AlertManager{
		config: cfg,
		db:     db,
	}
}

// ProcessThreatAlert processes a threat alert for a device
func (am *AlertManager) ProcessThreatAlert(device *models.Device, analysis *ThreatAnalysisResult) error {
	// Create alert
	alert := &models.Alert{
		ID:        am.generateAlertID(),
		DeviceID:  device.ID,
		Type:      "threat_detected",
		Severity:  am.calculateSeverity(analysis.ThreatLevel),
		Title:     am.generateAlertTitle(device, analysis),
		Message:   am.generateAlertMessage(device, analysis),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save to database
	if err := am.db.SaveAlert(alert); err != nil {
		return fmt.Errorf("failed to save alert: %w", err)
	}

	// Send notifications if enabled
	if am.config.Notifications.Enabled {
		return am.sendNotifications(alert, device, analysis)
	}

	return nil
}

// calculateSeverity determines alert severity based on threat level
func (am *AlertManager) calculateSeverity(threatLevel int) string {
	switch {
	case threatLevel >= 8:
		return "critical"
	case threatLevel >= 6:
		return "high"
	case threatLevel >= 4:
		return "medium"
	default:
		return "low"
	}
}

// generateAlertTitle creates a descriptive alert title
func (am *AlertManager) generateAlertTitle(device *models.Device, analysis *ThreatAnalysisResult) string {
	if len(analysis.ThreatTypes) > 0 {
		return fmt.Sprintf("%s detected: %s (%s)", 
			analysis.ThreatTypes[0], 
			device.Name, 
			device.GetDeviceTypeIcon())
	}
	return fmt.Sprintf("Threat detected: %s (%s)", device.Name, device.GetDeviceTypeIcon())
}

// generateAlertMessage creates a detailed alert message
func (am *AlertManager) generateAlertMessage(device *models.Device, analysis *ThreatAnalysisResult) string {
	message := fmt.Sprintf("Device %s (%s) detected with threat level %d (confidence: %.1f%%)",
		device.Name, device.MAC, analysis.ThreatLevel, analysis.Confidence*100)

	if len(analysis.Indicators) > 0 {
		message += "\n\nIndicators:\n"
		for _, indicator := range analysis.Indicators {
			message += fmt.Sprintf("• %s\n", indicator)
		}
	}

	if len(analysis.Recommendations) > 0 {
		message += "\nRecommendations:\n"
		for _, rec := range analysis.Recommendations {
			message += fmt.Sprintf("• %s\n", rec)
		}
	}

	return message
}

// sendNotifications sends notifications through configured channels
func (am *AlertManager) sendNotifications(alert *models.Alert, device *models.Device, analysis *ThreatAnalysisResult) error {
	// Discord notification
	if am.config.Notifications.Discord && am.config.Notifications.WebhookURL != "" {
		if err := am.sendDiscordNotification(alert, device, analysis); err != nil {
			fmt.Printf("Failed to send Discord notification: %v\n", err)
		}
	}

	// Could add other notification channels here (email, SMS, etc.)
	
	return nil
}

// sendDiscordNotification sends notification to Discord webhook
func (am *AlertManager) sendDiscordNotification(alert *models.Alert, device *models.Device, analysis *ThreatAnalysisResult) error {
	// This would implement Discord webhook notification
	// For now, just print to console
	fmt.Printf("🚨 DISCORD ALERT: %s - %s\n", alert.Title, alert.Message)
	return nil
}

// generateAlertID generates a unique alert ID
func (am *AlertManager) generateAlertID() string {
	return fmt.Sprintf("alert_%d", time.Now().UnixNano())
}
