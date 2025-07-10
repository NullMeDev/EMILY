package hardware

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/models"
)

// ExternalHardwareManager manages external hardware devices
type ExternalHardwareManager struct {
	config          *config.Config
	devices         map[string]*ExternalDevice
	rtlsdrAvailable bool
	hackrfAvailable bool
	gqrxAvailable   bool
}

// ExternalDevice represents an external SDR device
type ExternalDevice struct {
	ID           string            `json:"id"`
	Type         string            `json:"type"`         // rtlsdr, hackrf, airspy, etc.
	Name         string            `json:"name"`
	SerialNumber string            `json:"serial_number"`
	Frequency    FrequencyRange    `json:"frequency"`
	SampleRate   int               `json:"sample_rate"`
	Available    bool              `json:"available"`
	Connected    bool              `json:"connected"`
	Capabilities map[string]bool   `json:"capabilities"`
	LastSeen     time.Time         `json:"last_seen"`
}

// FrequencyRange represents the frequency range of a device
type FrequencyRange struct {
	MinHz int64 `json:"min_hz"`
	MaxHz int64 `json:"max_hz"`
}

// SpectrumData represents spectrum analysis data
type SpectrumData struct {
	DeviceID      string    `json:"device_id"`
	Timestamp     time.Time `json:"timestamp"`
	CenterFreq    int64     `json:"center_freq"`
	SampleRate    int       `json:"sample_rate"`
	Bandwidth     int       `json:"bandwidth"`
	PowerSpectrum []float64 `json:"power_spectrum"`
	PeakFreq      int64     `json:"peak_freq"`
	PeakPower     float64   `json:"peak_power"`
}

// SignalAnalysis represents analysis of detected signals
type SignalAnalysis struct {
	Frequency     int64     `json:"frequency"`
	Power         float64   `json:"power"`
	Bandwidth     int       `json:"bandwidth"`
	Modulation    string    `json:"modulation"`
	SignalType    string    `json:"signal_type"`
	Confidence    float64   `json:"confidence"`
	Timestamp     time.Time `json:"timestamp"`
	ThreatLevel   int       `json:"threat_level"`
	Description   string    `json:"description"`
}

// NewExternalHardwareManager creates a new external hardware manager
func NewExternalHardwareManager(cfg *config.Config) (*ExternalHardwareManager, error) {
	manager := &ExternalHardwareManager{
		config:  cfg,
		devices: make(map[string]*ExternalDevice),
	}

	// Detect available hardware
	manager.detectAvailableHardware()

	// Scan for connected devices
	if err := manager.scanForDevices(); err != nil {
		return nil, fmt.Errorf("failed to scan for devices: %w", err)
	}

	return manager, nil
}

// detectAvailableHardware detects available SDR software
func (ehm *ExternalHardwareManager) detectAvailableHardware() {
	// Check for RTL-SDR tools
	if _, err := exec.LookPath("rtl_test"); err == nil {
		ehm.rtlsdrAvailable = true
	}
	if _, err := exec.LookPath("rtl_fm"); err == nil {
		ehm.rtlsdrAvailable = true
	}

	// Check for HackRF tools
	if _, err := exec.LookPath("hackrf_info"); err == nil {
		ehm.hackrfAvailable = true
	}

	// Check for GQRX (GUI SDR application)
	if _, err := exec.LookPath("gqrx"); err == nil {
		ehm.gqrxAvailable = true
	}

	fmt.Printf("External hardware detection: RTL-SDR=%v, HackRF=%v, GQRX=%v\n",
		ehm.rtlsdrAvailable, ehm.hackrfAvailable, ehm.gqrxAvailable)
}

// scanForDevices scans for connected SDR devices
func (ehm *ExternalHardwareManager) scanForDevices() error {
	// Scan for RTL-SDR devices
	if ehm.rtlsdrAvailable {
		if err := ehm.scanRTLSDR(); err != nil {
			fmt.Printf("RTL-SDR scan error: %v\n", err)
		}
	}

	// Scan for HackRF devices
	if ehm.hackrfAvailable {
		if err := ehm.scanHackRF(); err != nil {
			fmt.Printf("HackRF scan error: %v\n", err)
		}
	}

	return nil
}

// scanRTLSDR scans for RTL-SDR devices
func (ehm *ExternalHardwareManager) scanRTLSDR() error {
	cmd := exec.Command("rtl_test", "-t")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("rtl_test failed: %w", err)
	}

	// Parse RTL-SDR device information
	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if strings.Contains(line, "Found") && strings.Contains(line, "device") {
			// Extract device information
			re := regexp.MustCompile(`Found (\d+) device\(s\):`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				deviceCount, _ := strconv.Atoi(matches[1])
				
				// Parse individual device entries
				for j := 1; j <= deviceCount && i+j < len(lines); j++ {
					deviceLine := lines[i+j]
					if device := ehm.parseRTLSDRDevice(deviceLine, j-1); device != nil {
						ehm.devices[device.ID] = device
					}
				}
			}
		}
	}

	return nil
}

// parseRTLSDRDevice parses RTL-SDR device information
func (ehm *ExternalHardwareManager) parseRTLSDRDevice(deviceLine string, index int) *ExternalDevice {
	// Example: "  0:  Realtek, RTL2838UHIDIR, SN: 00000001"
	re := regexp.MustCompile(`\s*(\d+):\s*([^,]+),\s*([^,]+),\s*SN:\s*(\w+)`)
	matches := re.FindStringSubmatch(deviceLine)
	if len(matches) < 5 {
		return nil
	}

	deviceID := fmt.Sprintf("rtlsdr_%s", matches[4])
	
	device := &ExternalDevice{
		ID:           deviceID,
		Type:         "rtlsdr",
		Name:         fmt.Sprintf("%s %s", matches[2], matches[3]),
		SerialNumber: matches[4],
		Frequency: FrequencyRange{
			MinHz: 24000000,   // 24 MHz
			MaxHz: 1766000000, // 1.766 GHz (typical RTL-SDR range)
		},
		SampleRate:   2048000, // 2.048 MHz default
		Available:    true,
		Connected:    true,
		Capabilities: map[string]bool{
			"spectrum_analysis": true,
			"signal_detection":  true,
			"fm_demodulation":   true,
			"am_demodulation":   true,
		},
		LastSeen: time.Now(),
	}

	return device
}

// scanHackRF scans for HackRF devices
func (ehm *ExternalHardwareManager) scanHackRF() error {
	cmd := exec.Command("hackrf_info")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("hackrf_info failed: %w", err)
	}

	if strings.Contains(string(output), "Found HackRF") {
		// Parse HackRF device information
		device := &ExternalDevice{
			ID:   "hackrf_one",
			Type: "hackrf",
			Name: "HackRF One",
			Frequency: FrequencyRange{
				MinHz: 1000000,     // 1 MHz
				MaxHz: 6000000000,  // 6 GHz
			},
			SampleRate:   20000000, // 20 MHz default
			Available:    true,
			Connected:    true,
			Capabilities: map[string]bool{
				"spectrum_analysis": true,
				"signal_detection":  true,
				"transmit":          true,
				"sweep":             true,
				"wideband":          true,
			},
			LastSeen: time.Now(),
		}

		// Extract serial number if available
		re := regexp.MustCompile(`Serial number: ([a-fA-F0-9]+)`)
		if matches := re.FindStringSubmatch(string(output)); len(matches) > 1 {
			device.SerialNumber = matches[1]
			device.ID = fmt.Sprintf("hackrf_%s", matches[1])
		}

		ehm.devices[device.ID] = device
	}

	return nil
}

// PerformSpectrumAnalysis performs spectrum analysis using available SDR
func (ehm *ExternalHardwareManager) PerformSpectrumAnalysis(ctx context.Context, startFreq, endFreq int64, duration time.Duration) ([]*SpectrumData, error) {
	results := make([]*SpectrumData, 0)

	for _, device := range ehm.devices {
		if !device.Available || !device.Connected {
			continue
		}

		// Check if frequency range is supported
		if startFreq < device.Frequency.MinHz || endFreq > device.Frequency.MaxHz {
			continue
		}

		switch device.Type {
		case "rtlsdr":
			spectrum, err := ehm.rtlsdrSpectrumAnalysis(ctx, device, startFreq, endFreq, duration)
			if err == nil {
				results = append(results, spectrum...)
			}
		case "hackrf":
			spectrum, err := ehm.hackrfSpectrumAnalysis(ctx, device, startFreq, endFreq, duration)
			if err == nil {
				results = append(results, spectrum...)
			}
		}
	}

	return results, nil
}

// rtlsdrSpectrumAnalysis performs spectrum analysis using RTL-SDR
func (ehm *ExternalHardwareManager) rtlsdrSpectrumAnalysis(ctx context.Context, device *ExternalDevice, startFreq, endFreq int64, duration time.Duration) ([]*SpectrumData, error) {
	results := make([]*SpectrumData, 0)

	// Use rtl_power for spectrum analysis
	stepSize := int64(1000000) // 1 MHz steps
	for freq := startFreq; freq <= endFreq; freq += stepSize {
		bandwidthHz := int(stepSize)
		if freq+stepSize > endFreq {
			bandwidthHz = int(endFreq - freq)
		}

		cmd := exec.CommandContext(ctx, "rtl_power",
			"-f", fmt.Sprintf("%d:%d:%d", freq, freq+stepSize, stepSize/10),
			"-g", "50", // High gain
			"-i", "1",  // Integration interval
			"-1",       // Single run
		)

		output, err := cmd.Output()
		if err != nil {
			continue
		}

		// Parse rtl_power output
		spectrum := ehm.parseRTLPowerOutput(device.ID, string(output), freq, bandwidthHz)
		if spectrum != nil {
			results = append(results, spectrum)
		}
	}

	return results, nil
}

// hackrfSpectrumAnalysis performs spectrum analysis using HackRF
func (ehm *ExternalHardwareManager) hackrfSpectrumAnalysis(ctx context.Context, device *ExternalDevice, startFreq, endFreq int64, duration time.Duration) ([]*SpectrumData, error) {
	results := make([]*SpectrumData, 0)

	// Use hackrf_sweep for spectrum analysis
	cmd := exec.CommandContext(ctx, "hackrf_sweep",
		"-f", fmt.Sprintf("%d:%d", startFreq/1000000, endFreq/1000000), // MHz
		"-w", "1000000", // 1 MHz bin width
		"-l", "40",      // LNA gain
		"-g", "40",      // VGA gain
		"-n", "1",       // Single sweep
	)

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("hackrf_sweep failed: %w", err)
	}

	// Parse hackrf_sweep output
	spectrum := ehm.parseHackRFSweepOutput(device.ID, string(output))
	if spectrum != nil {
		results = append(results, spectrum)
	}

	return results, nil
}

// parseRTLPowerOutput parses rtl_power CSV output
func (ehm *ExternalHardwareManager) parseRTLPowerOutput(deviceID, output string, centerFreq int64, bandwidth int) *SpectrumData {
	lines := strings.Split(output, "\n")
	if len(lines) == 0 {
		return nil
	}

	// Parse CSV data (frequency, power level)
	powerData := make([]float64, 0)
	var peakPower float64 = -999
	var peakFreq int64

	for _, line := range lines {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 6 {
			// RTL-power format: date, time, Hz low, Hz high, Hz step, samples, dB, dB, ...
			for i := 6; i < len(fields); i++ {
				if power, err := strconv.ParseFloat(fields[i], 64); err == nil {
					powerData = append(powerData, power)
					if power > peakPower {
						peakPower = power
						peakFreq = centerFreq + int64(i-6)*int64(bandwidth)/int64(len(fields)-6)
					}
				}
			}
		}
	}

	if len(powerData) == 0 {
		return nil
	}

	return &SpectrumData{
		DeviceID:      deviceID,
		Timestamp:     time.Now(),
		CenterFreq:    centerFreq,
		SampleRate:    2048000, // RTL-SDR default
		Bandwidth:     bandwidth,
		PowerSpectrum: powerData,
		PeakFreq:      peakFreq,
		PeakPower:     peakPower,
	}
}

// parseHackRFSweepOutput parses hackrf_sweep output
func (ehm *ExternalHardwareManager) parseHackRFSweepOutput(deviceID, output string) *SpectrumData {
	lines := strings.Split(output, "\n")
	powerData := make([]float64, 0)
	var peakPower float64 = -999
	var peakFreq int64
	var centerFreq int64

	for _, line := range lines {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 3 {
			// HackRF sweep format: date, time, freq_hz, power_db
			if freq, err := strconv.ParseInt(fields[2], 10, 64); err == nil {
				if power, err := strconv.ParseFloat(fields[3], 64); err == nil {
					powerData = append(powerData, power)
					if power > peakPower {
						peakPower = power
						peakFreq = freq
					}
					if centerFreq == 0 {
						centerFreq = freq
					}
				}
			}
		}
	}

	if len(powerData) == 0 {
		return nil
	}

	return &SpectrumData{
		DeviceID:      deviceID,
		Timestamp:     time.Now(),
		CenterFreq:    centerFreq,
		SampleRate:    20000000, // HackRF default
		Bandwidth:     int(peakFreq - centerFreq),
		PowerSpectrum: powerData,
		PeakFreq:      peakFreq,
		PeakPower:     peakPower,
	}
}

// AnalyzeSignals analyzes spectrum data for suspicious signals
func (ehm *ExternalHardwareManager) AnalyzeSignals(spectrumData []*SpectrumData) ([]*SignalAnalysis, error) {
	analyses := make([]*SignalAnalysis, 0)

	for _, spectrum := range spectrumData {
		// Look for suspicious signal patterns
		signals := ehm.detectSuspiciousSignals(spectrum)
		analyses = append(analyses, signals...)
	}

	return analyses, nil
}

// detectSuspiciousSignals detects suspicious signals in spectrum data
func (ehm *ExternalHardwareManager) detectSuspiciousSignals(spectrum *SpectrumData) []*SignalAnalysis {
	signals := make([]*SignalAnalysis, 0)

	// Define power threshold for signal detection
	noiseFloor := ehm.calculateNoiseFloor(spectrum.PowerSpectrum)
	threshold := noiseFloor + 10 // 10 dB above noise floor

	// Scan for signals above threshold
	for i, power := range spectrum.PowerSpectrum {
		if power > threshold {
			freq := spectrum.CenterFreq + int64(i)*int64(spectrum.Bandwidth)/int64(len(spectrum.PowerSpectrum))
			
			signal := &SignalAnalysis{
				Frequency:   freq,
				Power:       power,
				Bandwidth:   spectrum.Bandwidth / len(spectrum.PowerSpectrum),
				Timestamp:   spectrum.Timestamp,
				ThreatLevel: ehm.assessSignalThreat(freq, power),
			}

			// Determine signal type and modulation
			signal.SignalType, signal.Modulation = ehm.classifySignal(freq, power)
			signal.Confidence = ehm.calculateSignalConfidence(signal)
			signal.Description = ehm.generateSignalDescription(signal)

			signals = append(signals, signal)
		}
	}

	return signals
}

// calculateNoiseFloor calculates the noise floor from power spectrum
func (ehm *ExternalHardwareManager) calculateNoiseFloor(powerSpectrum []float64) float64 {
	if len(powerSpectrum) == 0 {
		return -100
	}

	// Calculate median power as noise floor estimate
	powers := make([]float64, len(powerSpectrum))
	copy(powers, powerSpectrum)
	
	// Simple median calculation
	total := 0.0
	for _, power := range powers {
		total += power
	}
	
	return total / float64(len(powers)) - 5 // 5 dB below average
}

// assessSignalThreat assesses threat level of a detected signal
func (ehm *ExternalHardwareManager) assessSignalThreat(frequency int64, power float64) int {
	threatLevel := 0

	// Frequency-based threat assessment
	switch {
	case frequency >= 2400000000 && frequency <= 2500000000: // 2.4 GHz ISM band
		threatLevel = 3 // WiFi, Bluetooth, surveillance devices
	case frequency >= 5000000000 && frequency <= 6000000000: // 5 GHz
		threatLevel = 2 // WiFi, some surveillance
	case frequency >= 800000000 && frequency <= 1000000000: // Cellular bands
		threatLevel = 5 // Potential IMSI catcher
	case frequency >= 13560000 && frequency <= 13560001: // NFC
		threatLevel = 4 // Close proximity threats
	case frequency >= 315000000 && frequency <= 433920000: // ISM bands
		threatLevel = 6 // Remote controls, surveillance transmitters
	default:
		threatLevel = 1 // Unknown frequency
	}

	// Power-based threat assessment boost
	if power > -30 { // Very strong signal
		threatLevel += 2
	} else if power > -50 { // Strong signal
		threatLevel += 1
	}

	if threatLevel > 10 {
		threatLevel = 10
	}

	return threatLevel
}

// classifySignal attempts to classify the signal type and modulation
func (ehm *ExternalHardwareManager) classifySignal(frequency int64, power float64) (string, string) {
	switch {
	case frequency >= 2400000000 && frequency <= 2500000000:
		return "WiFi/Bluetooth", "OFDM/FHSS"
	case frequency >= 5000000000 && frequency <= 6000000000:
		return "WiFi", "OFDM"
	case frequency >= 800000000 && frequency <= 1000000000:
		return "Cellular", "TDMA/CDMA"
	case frequency >= 315000000 && frequency <= 433920000:
		return "Remote Control", "ASK/FSK"
	case frequency >= 13560000 && frequency <= 13560001:
		return "NFC", "ASK"
	default:
		return "Unknown", "Unknown"
	}
}

// calculateSignalConfidence calculates confidence in signal classification
func (ehm *ExternalHardwareManager) calculateSignalConfidence(signal *SignalAnalysis) float64 {
	confidence := 0.5 // Base confidence

	// Higher confidence for known frequency bands
	switch signal.SignalType {
	case "WiFi/Bluetooth", "WiFi", "Cellular", "NFC":
		confidence += 0.3
	case "Remote Control":
		confidence += 0.2
	}

	// Higher confidence for stronger signals
	if signal.Power > -30 {
		confidence += 0.2
	} else if signal.Power > -50 {
		confidence += 0.1
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// generateSignalDescription generates human-readable signal description
func (ehm *ExternalHardwareManager) generateSignalDescription(signal *SignalAnalysis) string {
	return fmt.Sprintf("%s signal at %.2f MHz (%.1f dBm)", 
		signal.SignalType, float64(signal.Frequency)/1000000, signal.Power)
}

// GetConnectedDevices returns list of connected external devices
func (ehm *ExternalHardwareManager) GetConnectedDevices() []*ExternalDevice {
	devices := make([]*ExternalDevice, 0, len(ehm.devices))
	for _, device := range ehm.devices {
		if device.Connected {
			devices = append(devices, device)
		}
	}
	return devices
}

// IsHardwareAvailable checks if any external hardware is available
func (ehm *ExternalHardwareManager) IsHardwareAvailable() bool {
	return ehm.rtlsdrAvailable || ehm.hackrfAvailable
}

// GetCapabilities returns external hardware capabilities
func (ehm *ExternalHardwareManager) GetCapabilities() map[string]bool {
	capabilities := map[string]bool{
		"rtlsdr_available":     ehm.rtlsdrAvailable,
		"hackrf_available":     ehm.hackrfAvailable,
		"gqrx_available":       ehm.gqrxAvailable,
		"spectrum_analysis":    len(ehm.devices) > 0,
		"wideband_monitoring":  ehm.hackrfAvailable,
		"signal_transmission":  ehm.hackrfAvailable,
	}

	return capabilities
}
