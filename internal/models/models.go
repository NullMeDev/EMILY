package models

import (
	"strings"
	"time"
)

// Device represents a detected wireless device
type Device struct {
	ID           string    `json:"id" db:"id"`
	Type         string    `json:"type" db:"type"`           // wifi, bluetooth, cellular, nfc
	MAC          string    `json:"mac" db:"mac"`             // MAC address or identifier
	Name         string    `json:"name" db:"name"`           // Device name if available
	Manufacturer string    `json:"manufacturer" db:"manufacturer"`
	SignalLevel  int       `json:"signal_level" db:"signal_level"`
	Channel      int       `json:"channel" db:"channel"`
	Frequency    int       `json:"frequency" db:"frequency"`
	Encryption   string    `json:"encryption" db:"encryption"`
	FirstSeen    time.Time `json:"first_seen" db:"first_seen"`
	LastSeen     time.Time `json:"last_seen" db:"last_seen"`
	SeenCount    int       `json:"seen_count" db:"seen_count"`
	IsWhitelisted bool     `json:"is_whitelisted" db:"is_whitelisted"`
	ThreatLevel  int       `json:"threat_level" db:"threat_level"`
	Latitude     float64   `json:"latitude" db:"latitude"`
	Longitude    float64   `json:"longitude" db:"longitude"`
	Notes        string    `json:"notes" db:"notes"`
	RawData      string    `json:"raw_data" db:"raw_data"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// WiFiDevice represents a Wi-Fi access point or device
type WiFiDevice struct {
	Device
	SSID         string   `json:"ssid" db:"ssid"`
	BSSID        string   `json:"bssid" db:"bssid"`
	Hidden       bool     `json:"hidden" db:"hidden"`
	Capabilities []string `json:"capabilities" db:"capabilities"`
	Vendor       string   `json:"vendor" db:"vendor"`
	Country      string   `json:"country" db:"country"`
	Mode         string   `json:"mode" db:"mode"` // AP, STA, IBSS, etc.
	Beacons      []Beacon `json:"beacons,omitempty"`
	Clients      []string `json:"clients,omitempty"`
	Handshake    bool     `json:"handshake" db:"handshake"`
	Cracked      bool     `json:"cracked" db:"cracked"`
	Password     string   `json:"password,omitempty" db:"password"`
	WPS          bool     `json:"wps" db:"wps"`
}

// BluetoothDevice represents a Bluetooth device
type BluetoothDevice struct {
	Device
	Address       string            `json:"address" db:"address"`
	Class         string            `json:"class" db:"class"`
	Services      []string          `json:"services" db:"services"`
	Paired        bool              `json:"paired" db:"paired"`
	Connected     bool              `json:"connected" db:"connected"`
	RSSI          int               `json:"rssi" db:"rssi"`
	TxPower       int               `json:"tx_power" db:"tx_power"`
	Version       string            `json:"version" db:"version"`
	Advertisement map[string]string `json:"advertisement,omitempty" db:"advertisement"`
	IsLE          bool              `json:"is_le" db:"is_le"`
}

// CellularDevice represents a cellular tower or device
type CellularDevice struct {
	Device
	CellID         string         `json:"cell_id" db:"cell_id"`
	LAC            string         `json:"lac" db:"lac"`
	MCC            string         `json:"mcc" db:"mcc"`
	MNC            string         `json:"mnc" db:"mnc"`
	Technology     string         `json:"technology" db:"technology"` // GSM, UMTS, LTE, 5G
	Operator       string         `json:"operator" db:"operator"`
	SignalStrength int            `json:"signal_strength" db:"signal_strength"`
	Quality        int            `json:"quality" db:"quality"`
	Neighboring    []NeighborCell `json:"neighboring,omitempty"`
	IMSICatcher    bool           `json:"imsi_catcher_suspected" db:"imsi_catcher_suspected"`
}

// Beacon represents a WiFi beacon frame
type Beacon struct {
	Timestamp   time.Time `json:"timestamp"`
	SignalLevel int       `json:"signal_level"`
	Channel     int       `json:"channel"`
	Rate        string    `json:"rate"`
	Privacy     bool      `json:"privacy"`
}

// NeighborCell represents a neighboring cell tower
type NeighborCell struct {
	CellID   string `json:"cell_id"`
	LAC      string `json:"lac"`
	Signal   int    `json:"signal"`
	Distance int    `json:"distance"`
}

// NFCDevice represents an NFC tag or device
type NFCDevice struct {
	Device
	TagType      string            `json:"tag_type" db:"tag_type"`
	UID          string            `json:"uid" db:"uid"`
	ATR          string            `json:"atr" db:"atr"`
	Technology   string            `json:"technology" db:"technology"`
	IsActive     bool              `json:"is_active" db:"is_active"`
	ATQA         string            `json:"atqa,omitempty"`
	SAK          string            `json:"sak,omitempty"`
	ATS          string            `json:"ats,omitempty"`
	Applications []NFCApplication  `json:"applications,omitempty"`
	Data         map[string]string `json:"data,omitempty"`
}

// NFCApplication represents an NFC application
type NFCApplication struct {
	AID        string `json:"aid"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Selectable bool   `json:"selectable"`
	Priority   int    `json:"priority"`
}

// NetworkBaseline represents a network environment baseline
type NetworkBaseline struct {
	ID                string            `json:"id"`
	Timestamp         time.Time         `json:"timestamp"`
	NetworksDetected  int               `json:"networks_detected"`
	DevicesDetected   int               `json:"devices_detected"`
	SignalEnvironment map[string]float64 `json:"signal_environment"`
	ThreatLevel       int               `json:"threat_level"`
	Location          *Location         `json:"location,omitempty"`
}

// IntrusionAlert represents an intrusion detection alert
type IntrusionAlert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
	Resolved    bool                   `json:"resolved"`
}

// PasswordAttempt represents a password cracking attempt
type PasswordAttempt struct {
	ID          string    `json:"id"`
	TargetBSSID string    `json:"target_bssid"`
	TargetSSID  string    `json:"target_ssid"`
	Method      string    `json:"method"`
	Wordlist    string    `json:"wordlist"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Success     bool      `json:"success"`
	Password    string    `json:"password,omitempty"`
	KeysPerSec  int       `json:"keys_per_sec"`
}

// ThreatAssessment represents a threat analysis for a device
type ThreatAssessment struct {
	ID          string    `json:"id" db:"id"`
	DeviceID    string    `json:"device_id" db:"device_id"`
	ThreatType  string    `json:"threat_type" db:"threat_type"` // camera, audio, tracker, rogue_ap, etc.
	Score       float64   `json:"score" db:"score"`             // 0-10 threat score
	Confidence  float64   `json:"confidence" db:"confidence"`   // 0-1 confidence level
	Indicators  []string  `json:"indicators" db:"indicators"`   // List of threat indicators
	Description string    `json:"description" db:"description"`
	Mitigation  string    `json:"mitigation" db:"mitigation"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// ScanSession represents a scanning session
type ScanSession struct {
	ID            string    `json:"id" db:"id"`
	StartTime     time.Time `json:"start_time" db:"start_time"`
	EndTime       *time.Time `json:"end_time" db:"end_time"`
	Duration      int       `json:"duration" db:"duration"` // in seconds
	DevicesFound  int       `json:"devices_found" db:"devices_found"`
	ThreatsFound  int       `json:"threats_found" db:"threats_found"`
	ScanType      string    `json:"scan_type" db:"scan_type"` // full, quick, targeted
	Location      string    `json:"location" db:"location"`
	Notes         string    `json:"notes" db:"notes"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

// Alert represents a security alert
type Alert struct {
	ID          string    `json:"id" db:"id"`
	DeviceID    string    `json:"device_id" db:"device_id"`
	SessionID   string    `json:"session_id" db:"session_id"`
	Type        string    `json:"type" db:"type"`        // new_device, threat_detected, signal_loss, etc.
	Severity    string    `json:"severity" db:"severity"` // low, medium, high, critical
	Title       string    `json:"title" db:"title"`
	Message     string    `json:"message" db:"message"`
	Acknowledged bool     `json:"acknowledged" db:"acknowledged"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Location represents a geographical location
type Location struct {
	ID          string    `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	Latitude    float64   `json:"latitude" db:"latitude"`
	Longitude   float64   `json:"longitude" db:"longitude"`
	Radius      float64   `json:"radius" db:"radius"` // in meters
	IsGeofence  bool      `json:"is_geofence" db:"is_geofence"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Whitelist represents whitelisted devices
type Whitelist struct {
	ID          string    `json:"id" db:"id"`
	DeviceType  string    `json:"device_type" db:"device_type"`
	Identifier  string    `json:"identifier" db:"identifier"` // MAC, SSID, etc.
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	IsActive    bool      `json:"is_active" db:"is_active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Statistics represents scanning statistics
type Statistics struct {
	ID                string    `json:"id" db:"id"`
	Date              time.Time `json:"date" db:"date"`
	TotalScans        int       `json:"total_scans" db:"total_scans"`
	TotalDevices      int       `json:"total_devices" db:"total_devices"`
	NewDevices        int       `json:"new_devices" db:"new_devices"`
	ThreatsDetected   int       `json:"threats_detected" db:"threats_detected"`
	WiFiDevices       int       `json:"wifi_devices" db:"wifi_devices"`
	BluetoothDevices  int       `json:"bluetooth_devices" db:"bluetooth_devices"`
	CellularDevices   int       `json:"cellular_devices" db:"cellular_devices"`
	NFCDevices        int       `json:"nfc_devices" db:"nfc_devices"`
	AvgScanDuration   float64   `json:"avg_scan_duration" db:"avg_scan_duration"`
	AvgSignalStrength float64   `json:"avg_signal_strength" db:"avg_signal_strength"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
}

// ScanResult represents the result of a scan operation
type ScanResult struct {
	SessionID     string            `json:"session_id"`
	Duration      time.Duration     `json:"duration"`
	DevicesFound  []Device          `json:"devices_found"`
	ThreatsFound  []ThreatAssessment `json:"threats_found"`
	AlertsGenerated []Alert         `json:"alerts_generated"`
	Statistics    map[string]interface{} `json:"statistics"`
	Error         string            `json:"error,omitempty"`
}

// DeviceFilter represents filtering options for device queries
type DeviceFilter struct {
	Type         string    `json:"type,omitempty"`
	MinSignal    int       `json:"min_signal,omitempty"`
	MaxSignal    int       `json:"max_signal,omitempty"`
	Since        time.Time `json:"since,omitempty"`
	Until        time.Time `json:"until,omitempty"`
	ThreatLevel  int       `json:"threat_level,omitempty"`
	Whitelisted  *bool     `json:"whitelisted,omitempty"`
	Location     string    `json:"location,omitempty"`
	Manufacturer string    `json:"manufacturer,omitempty"`
	Limit        int       `json:"limit,omitempty"`
	Offset       int       `json:"offset,omitempty"`
}

// ExportFormat represents export format options
type ExportFormat struct {
	Type        string            `json:"type"`        // json, csv, pcap, kml
	Fields      []string          `json:"fields"`      // specific fields to export
	Filters     DeviceFilter      `json:"filters"`     // filters to apply
	Compression bool              `json:"compression"` // whether to compress output
	Encryption  bool              `json:"encryption"`  // whether to encrypt output
	Metadata    map[string]string `json:"metadata"`    // additional metadata
}

// IsTransient returns true if the device is considered transient
func (d *Device) IsTransient() bool {
	now := time.Now()
	return now.Sub(d.LastSeen) > 5*time.Minute && d.SeenCount < 3
}

// IsStatic returns true if the device is considered static/permanent
func (d *Device) IsStatic() bool {
	return d.SeenCount >= 10 && time.Since(d.FirstSeen) > 1*time.Hour
}

// GetAge returns the age of the device since first seen
func (d *Device) GetAge() time.Duration {
	return time.Since(d.FirstSeen)
}

// GetLastSeenAge returns the time since the device was last seen
func (d *Device) GetLastSeenAge() time.Duration {
	return time.Since(d.LastSeen)
}

// IsActive returns true if the device has been seen recently
func (d *Device) IsActive() bool {
	return time.Since(d.LastSeen) < 10*time.Minute
}

// GetThreatLevelString returns the threat level as a string
func (d *Device) GetThreatLevelString() string {
	switch d.ThreatLevel {
	case 0:
		return "None"
	case 1, 2:
		return "Low"
	case 3, 4:
		return "Medium"
	case 5, 6:
		return "High"
	case 7, 8, 9, 10:
		return "Critical"
	default:
		return "Unknown"
	}
}

// GetSignalStrengthString returns the signal strength as a descriptive string
func (d *Device) GetSignalStrengthString() string {
	switch {
	case d.SignalLevel > -30:
		return "Excellent"
	case d.SignalLevel > -50:
		return "Good"
	case d.SignalLevel > -70:
		return "Fair"
	case d.SignalLevel > -90:
		return "Poor"
	default:
		return "Very Poor"
	}
}

// IsSuspicious returns true if the device exhibits suspicious behavior
func (d *Device) IsSuspicious() bool {
	return d.ThreatLevel >= 5 || d.IsTransient() && d.SignalLevel > -40
}

// GetDeviceTypeIcon returns an icon/emoji for the device type
func (d *Device) GetDeviceTypeIcon() string {
	switch d.Type {
	case "wifi":
		return "📶"
	case "bluetooth":
		return "🔵"
	case "cellular":
		return "📱"
	case "nfc":
		return "📟"
	default:
		return "📡"
	}
}

// IsPotentialCamera returns true if the device might be a hidden camera
func (w *WiFiDevice) IsPotentialCamera() bool {
	suspiciousSSIDs := []string{
		"camera", "cam", "spy", "hidden", "secret", "surveillance",
		"monitor", "watch", "security", "guard", "eye", "lens",
	}
	
	for _, suspicious := range suspiciousSSIDs {
		if strings.Contains(strings.ToLower(w.SSID), suspicious) {
			return true
		}
	}
	
	// Check for common camera device manufacturers
	suspiciousVendors := []string{
		"hikvision", "dahua", "axis", "bosch", "panasonic",
		"sony", "samsung", "lg", "xiaomi", "tp-link",
	}
	
	for _, vendor := range suspiciousVendors {
		if strings.Contains(strings.ToLower(w.Manufacturer), vendor) {
			return true
		}
	}
	
	return false
}

// IsPotentialTracker returns true if the device might be a GPS tracker
func (b *BluetoothDevice) IsPotentialTracker() bool {
	// Check for common tracker services
	trackerServices := []string{
		"180f", // Battery Service (common in trackers)
		"1800", // Generic Access
		"1801", // Generic Attribute
		"fe9f", // Google Fast Pair (AirTags, etc.)
	}
	
	for _, service := range b.Services {
		for _, trackerService := range trackerServices {
			if strings.Contains(strings.ToLower(service), trackerService) {
				return true
			}
		}
	}
	
	// Check manufacturer data for known tracker signatures
	if advData, exists := b.Advertisement["manufacturer"]; exists {
		trackerManufacturers := []string{
			"apple", "tile", "chipolo", "samsung", "anker",
		}
		
		for _, manufacturer := range trackerManufacturers {
			if strings.Contains(strings.ToLower(advData), manufacturer) {
				return true
			}
		}
	}
	
	return false
}

// IsPotentialIMSICatcher returns true if the cellular device might be an IMSI catcher
func (c *CellularDevice) IsPotentialIMSICatcher() bool {
	// Check for suspicious characteristics
	if c.SignalStrength > -50 && (c.LAC == "0" || c.LAC == "") {
		return true
	}
	
	// Check for unusual network combinations
	if c.MCC == "0" || c.MNC == "0" || c.MCC == "" || c.MNC == "" {
		return true
	}
	
	// Check for known IMSI catcher signatures
	return c.IMSICatcher
}

