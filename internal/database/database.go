package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

// Database represents the database connection and operations
type Database struct {
	db     *sql.DB
	config *config.Config
}

// New creates a new database instance
func New(cfg *config.Config) (*Database, error) {
	// Ensure database directory exists
	dbPath := cfg.Storage.DatabasePath
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open database connection with pragmas for security and performance
	dsn := fmt.Sprintf("%s?_foreign_keys=on&_journal_mode=WAL&_cache=shared", dbPath)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)

	database := &Database{
		db:     db,
		config: cfg,
	}

	// Initialize database schema
	if err := database.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return database, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	return d.db.Close()
}

// initSchema creates the database tables
func (d *Database) initSchema() error {
	schema := `
	-- Devices table
	CREATE TABLE IF NOT EXISTS devices (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		mac TEXT,
		name TEXT,
		manufacturer TEXT,
		signal_level INTEGER,
		channel INTEGER,
		frequency INTEGER,
		encryption TEXT,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		seen_count INTEGER DEFAULT 1,
		is_whitelisted BOOLEAN DEFAULT FALSE,
		threat_level INTEGER DEFAULT 0,
		latitude REAL,
		longitude REAL,
		notes TEXT,
		raw_data TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- WiFi devices table
	CREATE TABLE IF NOT EXISTS wifi_devices (
		device_id TEXT PRIMARY KEY,
		ssid TEXT,
		bssid TEXT,
		hidden BOOLEAN DEFAULT FALSE,
		capabilities TEXT, -- JSON array
		vendor TEXT,
		country TEXT,
		mode TEXT,
		FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
	);

	-- Bluetooth devices table
	CREATE TABLE IF NOT EXISTS bluetooth_devices (
		device_id TEXT PRIMARY KEY,
		address TEXT,
		class INTEGER,
		services TEXT, -- JSON array
		is_le BOOLEAN DEFAULT FALSE,
		tx_power INTEGER,
		rssi INTEGER,
		adv_data TEXT, -- JSON object
		is_connected BOOLEAN DEFAULT FALSE,
		FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
	);

	-- Cellular devices table
	CREATE TABLE IF NOT EXISTS cellular_devices (
		device_id TEXT PRIMARY KEY,
		cell_id INTEGER,
		lac INTEGER,
		mcc INTEGER,
		mnc INTEGER,
		network_type TEXT,
		operator TEXT,
		signal_strength INTEGER,
		is_suspicious BOOLEAN DEFAULT FALSE,
		FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
	);

	-- NFC devices table
	CREATE TABLE IF NOT EXISTS nfc_devices (
		device_id TEXT PRIMARY KEY,
		tag_type TEXT,
		uid TEXT,
		atr TEXT,
		technology TEXT,
		is_active BOOLEAN DEFAULT FALSE,
		FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
	);

	-- Threat assessments table
	CREATE TABLE IF NOT EXISTS threat_assessments (
		id TEXT PRIMARY KEY,
		device_id TEXT NOT NULL,
		threat_type TEXT NOT NULL,
		score REAL NOT NULL,
		confidence REAL NOT NULL,
		indicators TEXT, -- JSON array
		description TEXT,
		mitigation TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
	);

	-- Scan sessions table
	CREATE TABLE IF NOT EXISTS scan_sessions (
		id TEXT PRIMARY KEY,
		start_time DATETIME NOT NULL,
		end_time DATETIME,
		duration INTEGER,
		devices_found INTEGER DEFAULT 0,
		threats_found INTEGER DEFAULT 0,
		scan_type TEXT,
		location TEXT,
		notes TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Alerts table
	CREATE TABLE IF NOT EXISTS alerts (
		id TEXT PRIMARY KEY,
		device_id TEXT,
		session_id TEXT,
		type TEXT NOT NULL,
		severity TEXT NOT NULL,
		title TEXT NOT NULL,
		message TEXT,
		acknowledged BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL,
		FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE SET NULL
	);

	-- Locations table
	CREATE TABLE IF NOT EXISTS locations (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		latitude REAL NOT NULL,
		longitude REAL NOT NULL,
		radius REAL DEFAULT 0,
		is_geofence BOOLEAN DEFAULT FALSE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Whitelist table
	CREATE TABLE IF NOT EXISTS whitelist (
		id TEXT PRIMARY KEY,
		device_type TEXT NOT NULL,
		identifier TEXT NOT NULL,
		name TEXT,
		description TEXT,
		is_active BOOLEAN DEFAULT TRUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Statistics table
	CREATE TABLE IF NOT EXISTS statistics (
		id TEXT PRIMARY KEY,
		date DATE NOT NULL,
		total_scans INTEGER DEFAULT 0,
		total_devices INTEGER DEFAULT 0,
		new_devices INTEGER DEFAULT 0,
		threats_detected INTEGER DEFAULT 0,
		wifi_devices INTEGER DEFAULT 0,
		bluetooth_devices INTEGER DEFAULT 0,
		cellular_devices INTEGER DEFAULT 0,
		nfc_devices INTEGER DEFAULT 0,
		avg_scan_duration REAL DEFAULT 0,
		avg_signal_strength REAL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Indexes for performance
	CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(type);
	CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
	CREATE INDEX IF NOT EXISTS idx_devices_threat_level ON devices(threat_level);
	CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
	CREATE INDEX IF NOT EXISTS idx_wifi_ssid ON wifi_devices(ssid);
	CREATE INDEX IF NOT EXISTS idx_wifi_bssid ON wifi_devices(bssid);
	CREATE INDEX IF NOT EXISTS idx_bluetooth_address ON bluetooth_devices(address);
	CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type);
	CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
	CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
	CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON scan_sessions(start_time);
	CREATE INDEX IF NOT EXISTS idx_whitelist_identifier ON whitelist(identifier);
	`

	_, err := d.db.Exec(schema)
	return err
}

// SaveDevice saves or updates a device in the database
func (d *Database) SaveDevice(device *models.Device) error {
	now := time.Now()
	device.UpdatedAt = now

	query := `
	INSERT INTO devices (
		id, type, mac, name, manufacturer, signal_level, channel, frequency,
		encryption, first_seen, last_seen, seen_count, is_whitelisted,
		threat_level, latitude, longitude, notes, raw_data, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		last_seen = excluded.last_seen,
		seen_count = seen_count + 1,
		signal_level = excluded.signal_level,
		name = COALESCE(excluded.name, name),
		manufacturer = COALESCE(excluded.manufacturer, manufacturer),
		threat_level = excluded.threat_level,
		latitude = excluded.latitude,
		longitude = excluded.longitude,
		notes = excluded.notes,
		raw_data = excluded.raw_data,
		updated_at = excluded.updated_at
	`

	_, err := d.db.Exec(query,
		device.ID, device.Type, device.MAC, device.Name, device.Manufacturer,
		device.SignalLevel, device.Channel, device.Frequency, device.Encryption,
		device.FirstSeen, device.LastSeen, device.SeenCount, device.IsWhitelisted,
		device.ThreatLevel, device.Latitude, device.Longitude, device.Notes,
		device.RawData, device.CreatedAt, device.UpdatedAt,
	)

	return err
}

// GetDevice retrieves a device by ID
func (d *Database) GetDevice(id string) (*models.Device, error) {
	query := `
	SELECT id, type, mac, name, manufacturer, signal_level, channel, frequency,
		   encryption, first_seen, last_seen, seen_count, is_whitelisted,
		   threat_level, latitude, longitude, notes, raw_data, created_at, updated_at
	FROM devices WHERE id = ?
	`

	var device models.Device
	err := d.db.QueryRow(query, id).Scan(
		&device.ID, &device.Type, &device.MAC, &device.Name, &device.Manufacturer,
		&device.SignalLevel, &device.Channel, &device.Frequency, &device.Encryption,
		&device.FirstSeen, &device.LastSeen, &device.SeenCount, &device.IsWhitelisted,
		&device.ThreatLevel, &device.Latitude, &device.Longitude, &device.Notes,
		&device.RawData, &device.CreatedAt, &device.UpdatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &device, nil
}

// GetDevices retrieves devices with optional filtering
func (d *Database) GetDevices(filter *models.DeviceFilter) ([]models.Device, error) {
	query := "SELECT id, type, mac, name, manufacturer, signal_level, channel, frequency, encryption, first_seen, last_seen, seen_count, is_whitelisted, threat_level, latitude, longitude, notes, raw_data, created_at, updated_at FROM devices WHERE 1=1"
	args := []interface{}{}

	if filter != nil {
		if filter.Type != "" {
			query += " AND type = ?"
			args = append(args, filter.Type)
		}
		if filter.MinSignal != 0 {
			query += " AND signal_level >= ?"
			args = append(args, filter.MinSignal)
		}
		if filter.MaxSignal != 0 {
			query += " AND signal_level <= ?"
			args = append(args, filter.MaxSignal)
		}
		if !filter.Since.IsZero() {
			query += " AND last_seen >= ?"
			args = append(args, filter.Since)
		}
		if !filter.Until.IsZero() {
			query += " AND last_seen <= ?"
			args = append(args, filter.Until)
		}
		if filter.ThreatLevel > 0 {
			query += " AND threat_level >= ?"
			args = append(args, filter.ThreatLevel)
		}
		if filter.Whitelisted != nil {
			query += " AND is_whitelisted = ?"
			args = append(args, *filter.Whitelisted)
		}
		if filter.Manufacturer != "" {
			query += " AND manufacturer LIKE ?"
			args = append(args, "%"+filter.Manufacturer+"%")
		}
	}

	query += " ORDER BY last_seen DESC"

	if filter != nil && filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []models.Device
	for rows.Next() {
		var device models.Device
		err := rows.Scan(
			&device.ID, &device.Type, &device.MAC, &device.Name, &device.Manufacturer,
			&device.SignalLevel, &device.Channel, &device.Frequency, &device.Encryption,
			&device.FirstSeen, &device.LastSeen, &device.SeenCount, &device.IsWhitelisted,
			&device.ThreatLevel, &device.Latitude, &device.Longitude, &device.Notes,
			&device.RawData, &device.CreatedAt, &device.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}

	return devices, rows.Err()
}

// DeleteOldDevices removes devices older than the configured retention period
func (d *Database) DeleteOldDevices() error {
	cutoff := time.Now().Add(-d.config.Core.DataRetention)
	
	query := "DELETE FROM devices WHERE last_seen < ? AND is_whitelisted = FALSE"
	result, err := d.db.Exec(query, cutoff)
	if err != nil {
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		fmt.Printf("Cleaned up %d old devices\n", rowsAffected)
	}

	return nil
}

// SaveAlert saves an alert to the database
func (d *Database) SaveAlert(alert *models.Alert) error {
	query := `
	INSERT INTO alerts (id, device_id, session_id, type, severity, title, message, acknowledged, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := d.db.Exec(query,
		alert.ID, alert.DeviceID, alert.SessionID, alert.Type, alert.Severity,
		alert.Title, alert.Message, alert.Acknowledged, alert.CreatedAt, alert.UpdatedAt,
	)

	return err
}

// GetUnacknowledgedAlerts retrieves unacknowledged alerts
func (d *Database) GetUnacknowledgedAlerts() ([]models.Alert, error) {
	query := `
	SELECT id, device_id, session_id, type, severity, title, message, acknowledged, created_at, updated_at
	FROM alerts WHERE acknowledged = FALSE ORDER BY created_at DESC
	`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []models.Alert
	for rows.Next() {
		var alert models.Alert
		err := rows.Scan(
			&alert.ID, &alert.DeviceID, &alert.SessionID, &alert.Type,
			&alert.Severity, &alert.Title, &alert.Message, &alert.Acknowledged,
			&alert.CreatedAt, &alert.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		alerts = append(alerts, alert)
	}

	return alerts, rows.Err()
}

// SaveScanSession saves a scan session
func (d *Database) SaveScanSession(session *models.ScanSession) error {
	query := `
	INSERT INTO scan_sessions (id, start_time, end_time, duration, devices_found, threats_found, scan_type, location, notes, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(id) DO UPDATE SET
		end_time = excluded.end_time,
		duration = excluded.duration,
		devices_found = excluded.devices_found,
		threats_found = excluded.threats_found,
		notes = excluded.notes
	`

	_, err := d.db.Exec(query,
		session.ID, session.StartTime, session.EndTime, session.Duration,
		session.DevicesFound, session.ThreatsFound, session.ScanType,
		session.Location, session.Notes, session.CreatedAt,
	)

	return err
}

// IsWhitelisted checks if a device identifier is whitelisted
func (d *Database) IsWhitelisted(deviceType, identifier string) (bool, error) {
	query := "SELECT COUNT(*) FROM whitelist WHERE device_type = ? AND identifier = ? AND is_active = TRUE"
	
	var count int
	err := d.db.QueryRow(query, deviceType, identifier).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// AddToWhitelist adds a device to the whitelist
func (d *Database) AddToWhitelist(entry *models.Whitelist) error {
	query := `
	INSERT INTO whitelist (id, device_type, identifier, name, description, is_active, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := d.db.Exec(query,
		entry.ID, entry.DeviceType, entry.Identifier, entry.Name,
		entry.Description, entry.IsActive, entry.CreatedAt, entry.UpdatedAt,
	)

	return err
}

// GetStatistics retrieves scanning statistics for a date range
func (d *Database) GetStatistics(since time.Time) (*models.Statistics, error) {
	query := `
	SELECT 
		COUNT(DISTINCT scan_sessions.id) as total_scans,
		COUNT(DISTINCT devices.id) as total_devices,
		COUNT(DISTINCT CASE WHEN devices.created_at >= ? THEN devices.id END) as new_devices,
		COUNT(DISTINCT threat_assessments.id) as threats_detected,
		COUNT(DISTINCT CASE WHEN devices.type = 'wifi' THEN devices.id END) as wifi_devices,
		COUNT(DISTINCT CASE WHEN devices.type = 'bluetooth' THEN devices.id END) as bluetooth_devices,
		COUNT(DISTINCT CASE WHEN devices.type = 'cellular' THEN devices.id END) as cellular_devices,
		COUNT(DISTINCT CASE WHEN devices.type = 'nfc' THEN devices.id END) as nfc_devices,
		AVG(scan_sessions.duration) as avg_scan_duration,
		AVG(devices.signal_level) as avg_signal_strength
	FROM scan_sessions
	LEFT JOIN devices ON devices.created_at >= scan_sessions.start_time AND devices.created_at <= COALESCE(scan_sessions.end_time, scan_sessions.start_time)
	LEFT JOIN threat_assessments ON threat_assessments.device_id = devices.id
	WHERE scan_sessions.start_time >= ?
	`

	var stats models.Statistics
	err := d.db.QueryRow(query, since, since).Scan(
		&stats.TotalScans, &stats.TotalDevices, &stats.NewDevices, &stats.ThreatsDetected,
		&stats.WiFiDevices, &stats.BluetoothDevices, &stats.CellularDevices, &stats.NFCDevices,
		&stats.AvgScanDuration, &stats.AvgSignalStrength,
	)

	if err != nil {
		return nil, err
	}

	stats.Date = time.Now()
	stats.CreatedAt = time.Now()

	return &stats, nil
}

// Vacuum performs database maintenance
func (d *Database) Vacuum() error {
	_, err := d.db.Exec("VACUUM")
	return err
}

// GetDatabaseSize returns the size of the database file in bytes
func (d *Database) GetDatabaseSize() (int64, error) {
	info, err := os.Stat(d.config.Storage.DatabasePath)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
