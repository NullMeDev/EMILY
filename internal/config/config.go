package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for PhantomScan
type Config struct {
	// Core settings
	Core CoreConfig `mapstructure:"core" json:"core"`
	
	// Detection settings
	Detection DetectionConfig `mapstructure:"detection" json:"detection"`
	
	// Stealth settings
	Stealth StealthConfig `mapstructure:"stealth" json:"stealth"`
	
	// Storage settings
	Storage StorageConfig `mapstructure:"storage" json:"storage"`
	
	// Notifications
	Notifications NotificationConfig `mapstructure:"notifications" json:"notifications"`
	
	// Android specific
	Android AndroidConfig `mapstructure:"android" json:"android"`
}

type CoreConfig struct {
	AppName         string        `mapstructure:"app_name" json:"app_name"`
	Version         string        `mapstructure:"version" json:"version"`
	Debug           bool          `mapstructure:"debug" json:"debug"`
	LogLevel        string        `mapstructure:"log_level" json:"log_level"`
	ScanInterval    time.Duration `mapstructure:"scan_interval" json:"scan_interval"`
	MaxDeviceAge    time.Duration `mapstructure:"max_device_age" json:"max_device_age"`
	DataRetention   time.Duration `mapstructure:"data_retention" json:"data_retention"`
}

type DetectionConfig struct {
	WiFi      WiFiConfig      `mapstructure:"wifi" json:"wifi"`
	Bluetooth BluetoothConfig `mapstructure:"bluetooth" json:"bluetooth"`
	Cellular  CellularConfig  `mapstructure:"cellular" json:"cellular"`
	NFC       NFCConfig       `mapstructure:"nfc" json:"nfc"`
	Threats   ThreatConfig    `mapstructure:"threats" json:"threats"`
}

type WiFiConfig struct {
	Enabled        bool     `mapstructure:"enabled" json:"enabled"`
	Interface      string   `mapstructure:"interface" json:"interface"`
	Channels       []int    `mapstructure:"channels" json:"channels"`
	ScanDuration   int      `mapstructure:"scan_duration" json:"scan_duration"`
	MinSignalLevel int      `mapstructure:"min_signal_level" json:"min_signal_level"`
	HiddenSSID     bool     `mapstructure:"hidden_ssid" json:"hidden_ssid"`
	Whitelist      []string `mapstructure:"whitelist" json:"whitelist"`
}

type BluetoothConfig struct {
	Enabled      bool     `mapstructure:"enabled" json:"enabled"`
	ScanDuration int      `mapstructure:"scan_duration" json:"scan_duration"`
	LowEnergy    bool     `mapstructure:"low_energy" json:"low_energy"`
	Classic      bool     `mapstructure:"classic" json:"classic"`
	Whitelist    []string `mapstructure:"whitelist" json:"whitelist"`
}

type CellularConfig struct {
	Enabled          bool `mapstructure:"enabled" json:"enabled"`
	IMSICatcher      bool `mapstructure:"imsi_catcher" json:"imsi_catcher"`
	SignalStrength   bool `mapstructure:"signal_strength" json:"signal_strength"`
	CellTowerMapping bool `mapstructure:"cell_tower_mapping" json:"cell_tower_mapping"`
}

type NFCConfig struct {
	Enabled     bool `mapstructure:"enabled" json:"enabled"`
	Passive     bool `mapstructure:"passive" json:"passive"`
	TagDetection bool `mapstructure:"tag_detection" json:"tag_detection"`
}

type ThreatConfig struct {
	HiddenCameras   bool `mapstructure:"hidden_cameras" json:"hidden_cameras"`
	AudioDevices    bool `mapstructure:"audio_devices" json:"audio_devices"`
	GPSTrackers     bool `mapstructure:"gps_trackers" json:"gps_trackers"`
	RogueAPs        bool `mapstructure:"rogue_aps" json:"rogue_aps"`
	UnknownDevices  bool `mapstructure:"unknown_devices" json:"unknown_devices"`
}

type StealthConfig struct {
	HiddenMode       bool   `mapstructure:"hidden_mode" json:"hidden_mode"`
	FakeAppName      string `mapstructure:"fake_app_name" json:"fake_app_name"`
	FakeIcon         string `mapstructure:"fake_icon" json:"fake_icon"`
	SilentMode       bool   `mapstructure:"silent_mode" json:"silent_mode"`
	AntiForensics    bool   `mapstructure:"anti_forensics" json:"anti_forensics"`
	EncryptedStorage bool   `mapstructure:"encrypted_storage" json:"encrypted_storage"`
	RemoteWipe       bool   `mapstructure:"remote_wipe" json:"remote_wipe"`
	MACRandomization bool   `mapstructure:"mac_randomization" json:"mac_randomization"`
}

type StorageConfig struct {
	DatabasePath   string `mapstructure:"database_path" json:"database_path"`
	CachePath      string `mapstructure:"cache_path" json:"cache_path"`
	LogPath        string `mapstructure:"log_path" json:"log_path"`
	MaxSize        int64  `mapstructure:"max_size" json:"max_size"`
	CompressLogs   bool   `mapstructure:"compress_logs" json:"compress_logs"`
	EncryptionKey  string `mapstructure:"encryption_key" json:"encryption_key"`
}

type NotificationConfig struct {
	Enabled    bool   `mapstructure:"enabled" json:"enabled"`
	Discord    bool   `mapstructure:"discord" json:"discord"`
	WebhookURL string `mapstructure:"webhook_url" json:"webhook_url"`
	Alerts     struct {
		NewDevice     bool `mapstructure:"new_device" json:"new_device"`
		ThreatLevel   int  `mapstructure:"threat_level" json:"threat_level"`
		SignalLoss    bool `mapstructure:"signal_loss" json:"signal_loss"`
		Surveillance  bool `mapstructure:"surveillance" json:"surveillance"`
	} `mapstructure:"alerts" json:"alerts"`
}

type AndroidConfig struct {
	ServiceName        string `mapstructure:"service_name" json:"service_name"`
	NotificationID     int    `mapstructure:"notification_id" json:"notification_id"`
	ForegroundService  bool   `mapstructure:"foreground_service" json:"foreground_service"`
	WakeLock          bool   `mapstructure:"wake_lock" json:"wake_lock"`
	BatteryOptimized  bool   `mapstructure:"battery_optimized" json:"battery_optimized"`
	BootStart         bool   `mapstructure:"boot_start" json:"boot_start"`
	RootRequired      bool   `mapstructure:"root_required" json:"root_required"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Core: CoreConfig{
			AppName:         "EMILY",
			Version:         "1.0.0-dev",
			Debug:           false,
			LogLevel:        "info",
			ScanInterval:    30 * time.Second,
			MaxDeviceAge:    24 * time.Hour,
			DataRetention:   7 * 24 * time.Hour,
		},
		Detection: DetectionConfig{
			WiFi: WiFiConfig{
				Enabled:        true,
				Channels:       []int{1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161},
				ScanDuration:   10,
				MinSignalLevel: -80,
				HiddenSSID:     true,
				Whitelist:      []string{},
			},
			Bluetooth: BluetoothConfig{
				Enabled:      true,
				ScanDuration: 10,
				LowEnergy:    true,
				Classic:      true,
				Whitelist:    []string{},
			},
			Cellular: CellularConfig{
				Enabled:          true,
				IMSICatcher:      true,
				SignalStrength:   true,
				CellTowerMapping: true,
			},
			NFC: NFCConfig{
				Enabled:     true,
				Passive:     true,
				TagDetection: true,
			},
			Threats: ThreatConfig{
				HiddenCameras:  true,
				AudioDevices:   true,
				GPSTrackers:    true,
				RogueAPs:       true,
				UnknownDevices: true,
			},
		},
		Stealth: StealthConfig{
			HiddenMode:       true,
			FakeAppName:      "System Update",
			FakeIcon:         "system_update",
			SilentMode:       true,
			AntiForensics:    true,
			EncryptedStorage: true,
			RemoteWipe:       true,
			MACRandomization: true,
		},
		Storage: StorageConfig{
			DatabasePath:  "data/phantom.db",
			CachePath:     "cache/",
			LogPath:       "logs/",
			MaxSize:       100 * 1024 * 1024, // 100MB
			CompressLogs:  true,
			EncryptionKey: "", // Generated on first run
		},
		Notifications: NotificationConfig{
			Enabled:    true,
			Discord:    false,
			WebhookURL: "",
			Alerts: struct {
				NewDevice     bool `mapstructure:"new_device" json:"new_device"`
				ThreatLevel   int  `mapstructure:"threat_level" json:"threat_level"`
				SignalLoss    bool `mapstructure:"signal_loss" json:"signal_loss"`
				Surveillance  bool `mapstructure:"surveillance" json:"surveillance"`
			}{
				NewDevice:    true,
				ThreatLevel:  3,
				SignalLoss:   false,
				Surveillance: true,
			},
		},
		Android: AndroidConfig{
			ServiceName:       "com.system.update.service",
			NotificationID:    12345,
			ForegroundService: true,
			WakeLock:         true,
			BatteryOptimized: false,
			BootStart:        true,
			RootRequired:     false,
		},
	}
}

// LoadConfig loads configuration from file
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()
	
	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./config")
		viper.AddConfigPath("/etc/emily")
	}
	
	// Set environment variable prefix
	viper.SetEnvPrefix("EMILY")
	viper.AutomaticEnv()
	
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, use defaults
			return config, nil
		}
		return nil, fmt.Errorf("error reading config file: %w", err)
	}
	
	if err := viper.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}
	
	// Generate encryption key if not set
	if config.Storage.EncryptionKey == "" {
		key, err := generateEncryptionKey()
		if err != nil {
			return nil, fmt.Errorf("error generating encryption key: %w", err)
		}
		config.Storage.EncryptionKey = key
	}
	
	return config, nil
}

// SaveConfig saves configuration to file
func SaveConfig(config *Config, configPath string) error {
	if configPath == "" {
		configPath = "config.yaml"
	}
	
	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("error creating config directory: %w", err)
	}
	
	// Marshal config to YAML
	viper.Set("core", config.Core)
	viper.Set("detection", config.Detection)
	viper.Set("stealth", config.Stealth)
	viper.Set("storage", config.Storage)
	viper.Set("notifications", config.Notifications)
	viper.Set("android", config.Android)
	
	if err := viper.WriteConfigAs(configPath); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}
	
	return nil
}

// EncryptData encrypts data using AES-GCM
func (c *Config) EncryptData(data []byte) (string, error) {
	if !c.Stealth.EncryptedStorage {
		return string(data), nil
	}
	
	key := sha256.Sum256([]byte(c.Storage.EncryptionKey))
	
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptData decrypts data using AES-GCM
func (c *Config) DecryptData(encryptedData string) ([]byte, error) {
	if !c.Stealth.EncryptedStorage {
		return []byte(encryptedData), nil
	}
	
	key := sha256.Sum256([]byte(c.Storage.EncryptionKey))
	
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

// generateEncryptionKey generates a random encryption key
func generateEncryptionKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Core.AppName == "" {
		return fmt.Errorf("app_name cannot be empty")
	}
	
	if c.Core.ScanInterval < 1*time.Second {
		return fmt.Errorf("scan_interval must be at least 1 second")
	}
	
	if c.Storage.MaxSize < 1024*1024 {
		return fmt.Errorf("max_size must be at least 1MB")
	}
	
	return nil
}
