package autonomous

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/database"
)

// RFModule handles radio frequency operations and SDR integration
type RFModule struct {
	config *config.Config
	db     *database.Database
	
	// Hardware interfaces
	sdrDevices    []SDRDevice
	wifiAdapters  []WiFiAdapter
	btRadios      []BluetoothRadio
	
	// Operation state
	isScanning    bool
	activeOps     map[string]*RFOperation
}

// SDRDevice represents a Software Defined Radio device
type SDRDevice struct {
	ID          string  `json:"id"`
	Type        string  `json:"type"`        // hackrf, rtlsdr, plutosdr, usrp
	Name        string  `json:"name"`
	SerialNum   string  `json:"serial_num"`
	MinFreq     float64 `json:"min_freq"`    // Hz
	MaxFreq     float64 `json:"max_freq"`    // Hz
	SampleRate  int     `json:"sample_rate"` // samples/sec
	Connected   bool    `json:"connected"`
	Capabilities []string `json:"capabilities"`
}

// WiFiAdapter represents a WiFi adapter with monitor mode capability
type WiFiAdapter struct {
	ID          string   `json:"id"`
	Interface   string   `json:"interface"`
	Driver      string   `json:"driver"`
	MonitorMode bool     `json:"monitor_mode"`
	Channels    []int    `json:"channels"`
	Bands       []string `json:"bands"` // 2.4GHz, 5GHz, 6GHz
	TXPower     int      `json:"tx_power"`
	Connected   bool     `json:"connected"`
}

// BluetoothRadio represents a Bluetooth radio interface
type BluetoothRadio struct {
	ID          string   `json:"id"`
	Interface   string   `json:"interface"`
	Version     string   `json:"version"`
	LowEnergy   bool     `json:"low_energy"`
	Classic     bool     `json:"classic"`
	TXPower     int      `json:"tx_power"`
	Connected   bool     `json:"connected"`
}

// USBDevice represents a USB device for exploitation
type USBDevice struct {
	ID          string `json:"id"`
	VendorID    string `json:"vendor_id"`
	ProductID   string `json:"product_id"`
	Description string `json:"description"`
	Type        string `json:"type"` // hid, storage, serial
	Connected   bool   `json:"connected"`
}

// IRBlaster represents an infrared blaster
type IRBlaster struct {
	ID          string   `json:"id"`
	Interface   string   `json:"interface"`
	Frequency   []string `json:"frequency"` // supported frequencies
	MaxRange    int      `json:"max_range"` // meters
	Connected   bool     `json:"connected"`
}

// RFOperation represents an ongoing RF operation
type RFOperation struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	StartTime   time.Time              `json:"start_time"`
	Duration    time.Duration          `json:"duration"`
	Parameters  map[string]interface{} `json:"parameters"`
	Status      string                 `json:"status"`
	Results     map[string]interface{} `json:"results"`
}

// SpectrumData represents spectrum analysis data
type SpectrumData struct {
	Frequency   float64   `json:"frequency"`
	Power       float64   `json:"power"`
	Bandwidth   float64   `json:"bandwidth"`
	Modulation  string    `json:"modulation"`
	Timestamp   time.Time `json:"timestamp"`
	Duration    time.Duration `json:"duration"`
	Confidence  float64   `json:"confidence"`
}

// SignalAnalysis represents analyzed signal data
type SignalAnalysis struct {
	CenterFreq  float64            `json:"center_freq"`
	Bandwidth   float64            `json:"bandwidth"`
	Modulation  string             `json:"modulation"`
	Protocol    string             `json:"protocol"`
	BitRate     int                `json:"bit_rate"`
	Encoding    string             `json:"encoding"`
	Data        []byte             `json:"data"`
	Metadata    map[string]interface{} `json:"metadata"`
	Confidence  float64            `json:"confidence"`
}

// NewRFModule creates a new RF module
func NewRFModule(cfg *config.Config, db *database.Database) (*RFModule, error) {
	module := &RFModule{
		config:    cfg,
		db:        db,
		activeOps: make(map[string]*RFOperation),
	}
	
	// Detect and initialize hardware
	if err := module.detectHardware(); err != nil {
		return nil, fmt.Errorf("failed to detect RF hardware: %w", err)
	}
	
	return module, nil
}

// detectHardware detects available RF hardware
func (rf *RFModule) detectHardware() error {
	// Detect SDR devices
	if err := rf.detectSDRDevices(); err != nil {
		fmt.Printf("[RF] Warning: SDR detection failed: %v\n", err)
	}
	
	// Detect WiFi adapters
	if err := rf.detectWiFiAdapters(); err != nil {
		fmt.Printf("[RF] Warning: WiFi adapter detection failed: %v\n", err)
	}
	
	// Detect Bluetooth radios
	if err := rf.detectBluetoothRadios(); err != nil {
		fmt.Printf("[RF] Warning: Bluetooth detection failed: %v\n", err)
	}
	
	return nil
}

// detectSDRDevices detects connected SDR devices
func (rf *RFModule) detectSDRDevices() error {
	rf.sdrDevices = make([]SDRDevice, 0)
	
	// Detect RTL-SDR devices
	if err := rf.detectRTLSDR(); err == nil {
		fmt.Printf("[RF] RTL-SDR devices detected\n")
	}
	
	// Detect HackRF devices
	if err := rf.detectHackRF(); err == nil {
		fmt.Printf("[RF] HackRF devices detected\n")
	}
	
	// Detect PlutoSDR devices
	if err := rf.detectPlutoSDR(); err == nil {
		fmt.Printf("[RF] PlutoSDR devices detected\n")
	}
	
	return nil
}

// detectRTLSDR detects RTL-SDR dongles
func (rf *RFModule) detectRTLSDR() error {
	cmd := exec.Command("rtl_test", "-t")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if strings.Contains(line, "Found") && strings.Contains(line, "device") {
			device := SDRDevice{
				ID:           fmt.Sprintf("rtlsdr_%d", i),
				Type:         "rtlsdr",
				Name:         "RTL-SDR Dongle",
				MinFreq:      24e6,      // 24 MHz
				MaxFreq:      1766e6,    // 1.766 GHz
				SampleRate:   2048000,   // 2.048 MS/s
				Connected:    true,
				Capabilities: []string{"rx", "spectrum_analysis"},
			}
			rf.sdrDevices = append(rf.sdrDevices, device)
		}
	}
	
	return nil
}

// detectHackRF detects HackRF devices
func (rf *RFModule) detectHackRF() error {
	cmd := exec.Command("hackrf_info")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	
	if strings.Contains(string(output), "Found HackRF") {
		device := SDRDevice{
			ID:           "hackrf_0",
			Type:         "hackrf",
			Name:         "HackRF One",
			MinFreq:      1e6,       // 1 MHz
			MaxFreq:      6000e6,    // 6 GHz
			SampleRate:   20000000,  // 20 MS/s
			Connected:    true,
			Capabilities: []string{"rx", "tx", "spectrum_analysis", "signal_generation"},
		}
		rf.sdrDevices = append(rf.sdrDevices, device)
	}
	
	return nil
}

// detectPlutoSDR detects PlutoSDR devices
func (rf *RFModule) detectPlutoSDR() error {
	cmd := exec.Command("iio_info", "-s")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	
	if strings.Contains(string(output), "PlutoSDR") {
		device := SDRDevice{
			ID:           "plutosdr_0",
			Type:         "plutosdr",
			Name:         "PlutoSDR",
			MinFreq:      325e6,     // 325 MHz
			MaxFreq:      3800e6,    // 3.8 GHz
			SampleRate:   61440000,  // 61.44 MS/s
			Connected:    true,
			Capabilities: []string{"rx", "tx", "spectrum_analysis", "signal_generation"},
		}
		rf.sdrDevices = append(rf.sdrDevices, device)
	}
	
	return nil
}

// detectWiFiAdapters detects WiFi adapters with monitor mode capability
func (rf *RFModule) detectWiFiAdapters() error {
	rf.wifiAdapters = make([]WiFiAdapter, 0)
	
	// Get wireless interfaces
	cmd := exec.Command("iwconfig")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	
	lines := strings.Split(string(output), "\n")
	var currentInterface string
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "IEEE 802.11") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				currentInterface = parts[0]
				
				adapter := WiFiAdapter{
					ID:          fmt.Sprintf("wifi_%s", currentInterface),
					Interface:   currentInterface,
					MonitorMode: rf.checkMonitorMode(currentInterface),
					Channels:    []int{1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161},
					Bands:       []string{"2.4GHz", "5GHz"},
					Connected:   true,
				}
				
				rf.wifiAdapters = append(rf.wifiAdapters, adapter)
			}
		}
	}
	
	return nil
}

// checkMonitorMode checks if an interface supports monitor mode
func (rf *RFModule) checkMonitorMode(iface string) bool {
	cmd := exec.Command("iw", "dev", iface, "info")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	return strings.Contains(string(output), "monitor")
}

// detectBluetoothRadios detects Bluetooth radios
func (rf *RFModule) detectBluetoothRadios() error {
	rf.btRadios = make([]BluetoothRadio, 0)
	
	cmd := exec.Command("hciconfig")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "hci") && strings.Contains(line, ":") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				hciInterface := strings.TrimSuffix(parts[0], ":")
				
				radio := BluetoothRadio{
					ID:        fmt.Sprintf("bt_%s", hciInterface),
					Interface: hciInterface,
					Version:   "4.0+",
					LowEnergy: true,
					Classic:   true,
					Connected: true,
				}
				
				rf.btRadios = append(rf.btRadios, radio)
			}
		}
	}
	
	return nil
}

// WiFiSpectrumScan performs comprehensive WiFi spectrum analysis
func (rf *RFModule) WiFiSpectrumScan() error {
	fmt.Printf("[RF] Starting WiFi spectrum scan\n")
	
	for _, adapter := range rf.wifiAdapters {
		if !adapter.Connected {
			continue
		}
		
		// Enable monitor mode
		if err := rf.enableMonitorMode(adapter.Interface); err != nil {
			fmt.Printf("[RF] Failed to enable monitor mode on %s: %v\n", adapter.Interface, err)
			continue
		}
		
		// Scan all channels
		for _, channel := range adapter.Channels {
			if err := rf.scanWiFiChannel(adapter.Interface, channel); err != nil {
				fmt.Printf("[RF] Failed to scan channel %d: %v\n", channel, err)
			}
		}
		
		// Disable monitor mode
		rf.disableMonitorMode(adapter.Interface)
	}
	
	return nil
}

// enableMonitorMode enables monitor mode on WiFi interface
func (rf *RFModule) enableMonitorMode(iface string) error {
	// Take interface down
	exec.Command("ip", "link", "set", iface, "down").Run()
	
	// Set monitor mode
	cmd := exec.Command("iw", "dev", iface, "set", "type", "monitor")
	if err := cmd.Run(); err != nil {
		return err
	}
	
	// Bring interface up
	return exec.Command("ip", "link", "set", iface, "up").Run()
}

// disableMonitorMode disables monitor mode on WiFi interface
func (rf *RFModule) disableMonitorMode(iface string) error {
	// Take interface down
	exec.Command("ip", "link", "set", iface, "down").Run()
	
	// Set managed mode
	cmd := exec.Command("iw", "dev", iface, "set", "type", "managed")
	if err := cmd.Run(); err != nil {
		return err
	}
	
	// Bring interface up
	return exec.Command("ip", "link", "set", iface, "up").Run()
}

// scanWiFiChannel scans a specific WiFi channel
func (rf *RFModule) scanWiFiChannel(iface string, channel int) error {
	// Set channel
	cmd := exec.Command("iw", "dev", iface, "set", "channel", strconv.Itoa(channel))
	if err := cmd.Run(); err != nil {
		return err
	}
	
	// Capture packets for analysis
	cmd = exec.Command("timeout", "5", "tcpdump", "-i", iface, "-w", 
		fmt.Sprintf("/tmp/wifi_ch%d_%d.pcap", channel, time.Now().Unix()))
	cmd.Run() // Ignore errors for timeout command
	
	return nil
}

// BluetoothSpectrumScan performs Bluetooth spectrum analysis
func (rf *RFModule) BluetoothSpectrumScan() error {
	fmt.Printf("[RF] Starting Bluetooth spectrum scan\n")
	
	for _, radio := range rf.btRadios {
		if !radio.Connected {
			continue
		}
		
		// LE scan
		if radio.LowEnergy {
			rf.bluetoothLEScan(radio.Interface)
		}
		
		// Classic scan
		if radio.Classic {
			rf.bluetoothClassicScan(radio.Interface)
		}
	}
	
	return nil
}

// bluetoothLEScan performs Bluetooth Low Energy scanning
func (rf *RFModule) bluetoothLEScan(iface string) error {
	cmd := exec.Command("timeout", "10", "hcitool", "-i", iface, "lescan")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	
	// Parse and store results
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			// Process BLE device discovery
			fmt.Printf("[RF] BLE device: %s\n", line)
		}
	}
	
	return nil
}

// bluetoothClassicScan performs Bluetooth Classic scanning
func (rf *RFModule) bluetoothClassicScan(iface string) error {
	cmd := exec.Command("timeout", "10", "hcitool", "-i", iface, "scan")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	
	// Parse and store results
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ":") {
			// Process classic device discovery
			fmt.Printf("[RF] BT Classic device: %s\n", line)
		}
	}
	
	return nil
}

// SubGHzScan performs sub-GHz spectrum scanning
func (rf *RFModule) SubGHzScan() error {
	fmt.Printf("[RF] Starting Sub-GHz spectrum scan\n")
	
	// Find SDR device capable of sub-GHz
	var sdr *SDRDevice
	for _, device := range rf.sdrDevices {
		if device.Connected && device.MinFreq <= 1000e6 { // 1 GHz
			sdr = &device
			break
		}
	}
	
	if sdr == nil {
		return fmt.Errorf("no suitable SDR device for sub-GHz scanning")
	}
	
	// Common sub-GHz frequencies
	frequencies := []float64{
		315e6,  // 315 MHz
		433.92e6, // 433.92 MHz
		868e6,  // 868 MHz
		915e6,  // 915 MHz
	}
	
	for _, freq := range frequencies {
		if err := rf.scanFrequency(sdr, freq, 1e6); err != nil {
			fmt.Printf("[RF] Failed to scan %.2f MHz: %v\n", freq/1e6, err)
		}
	}
	
	return nil
}

// scanFrequency scans a specific frequency with given bandwidth
func (rf *RFModule) scanFrequency(sdr *SDRDevice, freq, bandwidth float64) error {
	switch sdr.Type {
	case "rtlsdr":
		return rf.rtlsdrScan(freq, bandwidth)
	case "hackrf":
		return rf.hackrfScan(freq, bandwidth)
	case "plutosdr":
		return rf.plutosdrScan(freq, bandwidth)
	default:
		return fmt.Errorf("unsupported SDR type: %s", sdr.Type)
	}
}

// rtlsdrScan performs RTL-SDR frequency scan
func (rf *RFModule) rtlsdrScan(freq, bandwidth float64) error {
	filename := fmt.Sprintf("/tmp/rtlsdr_%.0f_%d.raw", freq, time.Now().Unix())
	
	cmd := exec.Command("timeout", "5", "rtl_sdr", 
		"-f", fmt.Sprintf("%.0f", freq),
		"-s", "2048000",
		"-n", "10240000",
		filename)
	
	return cmd.Run()
}

// hackrfScan performs HackRF frequency scan
func (rf *RFModule) hackrfScan(freq, bandwidth float64) error {
	filename := fmt.Sprintf("/tmp/hackrf_%.0f_%d.raw", freq, time.Now().Unix())
	
	cmd := exec.Command("timeout", "5", "hackrf_transfer",
		"-r", filename,
		"-f", fmt.Sprintf("%.0f", freq),
		"-s", "20000000",
		"-n", "100000000")
	
	return cmd.Run()
}

// plutosdrScan performs PlutoSDR frequency scan
func (rf *RFModule) plutosdrScan(freq, bandwidth float64) error {
	// PlutoSDR scanning would use GNU Radio or custom application
	fmt.Printf("[RF] PlutoSDR scan at %.2f MHz\n", freq/1e6)
	return nil
}

// CellularScan performs cellular network scanning
func (rf *RFModule) CellularScan() error {
	fmt.Printf("[RF] Starting cellular network scan\n")
	
	// GSM bands
	gsmBands := []float64{
		850e6,  // GSM 850
		900e6,  // GSM 900
		1800e6, // GSM 1800
		1900e6, // GSM 1900
	}
	
	// LTE bands (simplified)
	lteBands := []float64{
		700e6,  // Band 12/17
		850e6,  // Band 5
		1900e6, // Band 2
		2100e6, // Band 1
	}
	
	// Scan GSM bands
	for _, freq := range gsmBands {
		rf.scanCellularBand("GSM", freq)
	}
	
	// Scan LTE bands
	for _, freq := range lteBands {
		rf.scanCellularBand("LTE", freq)
	}
	
	return nil
}

// scanCellularBand scans a specific cellular band
func (rf *RFModule) scanCellularBand(technology string, freq float64) error {
	fmt.Printf("[RF] Scanning %s band at %.2f MHz\n", technology, freq/1e6)
	
	// Use available SDR for cellular scanning
	for _, sdr := range rf.sdrDevices {
		if sdr.Connected && freq >= sdr.MinFreq && freq <= sdr.MaxFreq {
			return rf.scanFrequency(&sdr, freq, 200e3) // 200 kHz bandwidth
		}
	}
	
	return fmt.Errorf("no suitable SDR for frequency %.2f MHz", freq/1e6)
}

// BluetoothJam performs Bluetooth jamming
func (rf *RFModule) BluetoothJam(params map[string]interface{}) (bool, error) {
	fmt.Printf("[RF] Starting Bluetooth jamming\n")
	
	// Find HackRF or other TX-capable SDR
	var sdr *SDRDevice
	for _, device := range rf.sdrDevices {
		if device.Connected && contains(device.Capabilities, "tx") {
			sdr = &device
			break
		}
	}
	
	if sdr == nil {
		return false, fmt.Errorf("no TX-capable SDR available")
	}
	
	// Bluetooth frequency range: 2.4 - 2.485 GHz
	return rf.jamFrequencyRange(sdr, 2.4e9, 2.485e9)
}

// jamFrequencyRange jams a frequency range
func (rf *RFModule) jamFrequencyRange(sdr *SDRDevice, startFreq, endFreq float64) (bool, error) {
	switch sdr.Type {
	case "hackrf":
		return rf.hackrfJam(startFreq, endFreq)
	case "plutosdr":
		return rf.plutosdrJam(startFreq, endFreq)
	default:
		return false, fmt.Errorf("jamming not supported on %s", sdr.Type)
	}
}

// hackrfJam performs jamming using HackRF
func (rf *RFModule) hackrfJam(startFreq, endFreq float64) (bool, error) {
	// Generate noise signal
	cmd := exec.Command("timeout", "30", "hackrf_transfer",
		"-t", "/dev/urandom",
		"-f", fmt.Sprintf("%.0f", (startFreq+endFreq)/2),
		"-s", "20000000",
		"-x", "20") // TX gain
	
	err := cmd.Run()
	return err == nil, err
}

// plutosdrJam performs jamming using PlutoSDR
func (rf *RFModule) plutosdrJam(startFreq, endFreq float64) (bool, error) {
	fmt.Printf("[RF] PlutoSDR jamming from %.2f to %.2f MHz\n", startFreq/1e6, endFreq/1e6)
	// Implementation would use GNU Radio or PlutoSDR APIs
	return true, nil
}

// GetSpectrumData returns current spectrum analysis data
func (rf *RFModule) GetSpectrumData() []SpectrumData {
	// Return analyzed spectrum data
	return make([]SpectrumData, 0)
}

// AnalyzeSignal performs detailed signal analysis
func (rf *RFModule) AnalyzeSignal(freq float64, bandwidth float64) (*SignalAnalysis, error) {
	// Implement signal analysis logic
	analysis := &SignalAnalysis{
		CenterFreq: freq,
		Bandwidth:  bandwidth,
		Confidence: 0.8,
		Metadata:   make(map[string]interface{}),
	}
	
	return analysis, nil
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
