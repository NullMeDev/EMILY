package autonomous

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/database"
)

// ForensicModule handles evidence collection and analysis
type ForensicModule struct {
	config     *config.Config
	db         *database.Database
	evidenceDir string
	collections map[string]*EvidenceCollection
}

// EvidenceCollection represents a collection of evidence
type EvidenceCollection struct {
	ID          string         `json:"id"`
	StartTime   time.Time      `json:"start_time"`
	EndTime     *time.Time     `json:"end_time,omitempty"`
	ThreatID    string         `json:"threat_id"`
	Items       []EvidenceItem `json:"items"`
	Status      string         `json:"status"`
	Hash        string         `json:"hash"`
}

// NewForensicModule creates a new forensic module
func NewForensicModule(cfg *config.Config, db *database.Database) (*ForensicModule, error) {
	evidenceDir := "/tmp/emily_evidence"
	os.MkdirAll(evidenceDir, 0755)
	
	return &ForensicModule{
		config:      cfg,
		db:          db,
		evidenceDir: evidenceDir,
		collections: make(map[string]*EvidenceCollection),
	}, nil
}

// CollectEvidence collects evidence for a threat
func (fm *ForensicModule) CollectEvidence(params map[string]interface{}) (bool, error) {
	collectionID := fmt.Sprintf("evidence_%d", time.Now().Unix())
	
	collection := &EvidenceCollection{
		ID:        collectionID,
		StartTime: time.Now(),
		Items:     make([]EvidenceItem, 0),
		Status:    "collecting",
	}
	
	fm.collections[collectionID] = collection
	
	// Collect various types of evidence
	fm.collectNetworkEvidence(collection)
	fm.collectSignalEvidence(collection)
	fm.collectSystemEvidence(collection)
	
	collection.Status = "completed"
	now := time.Now()
	collection.EndTime = &now
	
	return true, nil
}

// ContinuousCollection performs continuous evidence collection
func (fm *ForensicModule) ContinuousCollection() {
	// Create timestamped evidence collection
	timestamp := time.Now().Format("20060102_150405")
	collectionDir := filepath.Join(fm.evidenceDir, timestamp)
	os.MkdirAll(collectionDir, 0755)
	
	// Network packet capture
	go fm.networkCapture(collectionDir, 5*time.Minute)
	
	// RF spectrum capture
	go fm.spectrumCapture(collectionDir, 3*time.Minute)
	
	// System state capture
	fm.systemStateCapture(collectionDir)
}

// collectNetworkEvidence collects network-related evidence
func (fm *ForensicModule) collectNetworkEvidence(collection *EvidenceCollection) {
	// WiFi scan evidence
	cmd := exec.Command("iwlist", "scan")
	output, err := cmd.Output()
	if err == nil {
		filename := fmt.Sprintf("wifi_scan_%d.txt", time.Now().Unix())
		filepath := filepath.Join(fm.evidenceDir, filename)
		os.WriteFile(filepath, output, 0644)
		
		collection.Items = append(collection.Items, EvidenceItem{
			Type:        "network_scan",
			Filename:    filename,
			Hash:        fm.calculateHash(filepath),
			Size:        int64(len(output)),
			Timestamp:   time.Now(),
			Description: "WiFi network scan results",
		})
	}
	
	// Bluetooth scan evidence
	cmd = exec.Command("hcitool", "scan")
	output, err = cmd.Output()
	if err == nil {
		filename := fmt.Sprintf("bt_scan_%d.txt", time.Now().Unix())
		filepath := filepath.Join(fm.evidenceDir, filename)
		os.WriteFile(filepath, output, 0644)
		
		collection.Items = append(collection.Items, EvidenceItem{
			Type:        "bluetooth_scan",
			Filename:    filename,
			Hash:        fm.calculateHash(filepath),
			Size:        int64(len(output)),
			Timestamp:   time.Now(),
			Description: "Bluetooth device scan results",
		})
	}
}

// collectSignalEvidence collects RF signal evidence
func (fm *ForensicModule) collectSignalEvidence(collection *EvidenceCollection) {
	// RTL-SDR capture if available
	cmd := exec.Command("rtl_sdr", "-f", "433920000", "-s", "2048000", "-n", "4096000", 
		fmt.Sprintf("%s/rf_433_%d.raw", fm.evidenceDir, time.Now().Unix()))
	
	if err := cmd.Run(); err == nil {
		// Add to evidence collection
		// Implementation details...
	}
}

// collectSystemEvidence collects system state evidence
func (fm *ForensicModule) collectSystemEvidence(collection *EvidenceCollection) {
	// System information
	systemInfo := fm.gatherSystemInfo()
	filename := fmt.Sprintf("system_info_%d.json", time.Now().Unix())
	filepath := filepath.Join(fm.evidenceDir, filename)
	
	// Write system info to file
	file, err := os.Create(filepath)
	if err == nil {
		file.WriteString(systemInfo)
		file.Close()
		
		collection.Items = append(collection.Items, EvidenceItem{
			Type:        "system_info",
			Filename:    filename,
			Hash:        fm.calculateHash(filepath),
			Timestamp:   time.Now(),
			Description: "System information snapshot",
		})
	}
}

// networkCapture performs network packet capture
func (fm *ForensicModule) networkCapture(dir string, duration time.Duration) {
	filename := filepath.Join(dir, "network_capture.pcap")
	cmd := exec.Command("timeout", fmt.Sprintf("%.0f", duration.Seconds()),
		"tcpdump", "-i", "any", "-w", filename)
	cmd.Run()
}

// spectrumCapture performs RF spectrum capture
func (fm *ForensicModule) spectrumCapture(dir string, duration time.Duration) {
	filename := filepath.Join(dir, "spectrum_capture.raw")
	cmd := exec.Command("timeout", fmt.Sprintf("%.0f", duration.Seconds()),
		"rtl_sdr", "-f", "2400000000", "-s", "2048000", filename)
	cmd.Run()
}

// systemStateCapture captures current system state
func (fm *ForensicModule) systemStateCapture(dir string) {
	// Process list
	cmd := exec.Command("ps", "aux")
	if output, err := cmd.Output(); err == nil {
		os.WriteFile(filepath.Join(dir, "processes.txt"), output, 0644)
	}
	
	// Network connections
	cmd = exec.Command("netstat", "-tuln")
	if output, err := cmd.Output(); err == nil {
		os.WriteFile(filepath.Join(dir, "netstat.txt"), output, 0644)
	}
	
	// System logs
	cmd = exec.Command("dmesg")
	if output, err := cmd.Output(); err == nil {
		os.WriteFile(filepath.Join(dir, "dmesg.txt"), output, 0644)
	}
}

// gatherSystemInfo gathers system information
func (fm *ForensicModule) gatherSystemInfo() string {
	info := fmt.Sprintf("Timestamp: %s\n", time.Now().Format(time.RFC3339))
	
	// Hostname
	if hostname, err := os.Hostname(); err == nil {
		info += fmt.Sprintf("Hostname: %s\n", hostname)
	}
	
	// Uptime
	if cmd := exec.Command("uptime"); cmd != nil {
		if output, err := cmd.Output(); err == nil {
			info += fmt.Sprintf("Uptime: %s\n", string(output))
		}
	}
	
	return info
}

// calculateHash calculates SHA256 hash of file
func (fm *ForensicModule) calculateHash(filepath string) string {
	file, err := os.Open(filepath)
	if err != nil {
		return ""
	}
	defer file.Close()
	
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}
	
	return fmt.Sprintf("%x", hash.Sum(nil))
}
