package autonomous

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/database"
)

// HardwareModule handles hardware security testing and sensor integration
type HardwareModule struct {
	config *config.Config
	db     *database.Database
	
	// Hardware capabilities
	gpioAvailable    bool
	cameraAvailable  bool
	audioAvailable   bool
	sensorsAvailable bool
	irBlasterAvailable bool
}

// NewHardwareModule creates a new hardware module
func NewHardwareModule(cfg *config.Config, db *database.Database) (*HardwareModule, error) {
	module := &HardwareModule{
		config: cfg,
		db:     db,
	}
	
	// Check hardware capabilities
	module.checkHardwareCapabilities()
	
	return module, nil
}

// checkHardwareCapabilities checks available hardware capabilities
func (hm *HardwareModule) checkHardwareCapabilities() {
	hm.gpioAvailable = hm.checkGPIO()
	hm.cameraAvailable = hm.checkCamera()
	hm.audioAvailable = hm.checkAudio()
	hm.sensorsAvailable = hm.checkSensors()
	hm.irBlasterAvailable = hm.checkIRBlaster()
	
	fmt.Printf("[HARDWARE] Capabilities: GPIO=%v, Camera=%v, Audio=%v, Sensors=%v, IR=%v\n",
		hm.gpioAvailable, hm.cameraAvailable, hm.audioAvailable, hm.sensorsAvailable, hm.irBlasterAvailable)
}

// checkGPIO checks if GPIO is available
func (hm *HardwareModule) checkGPIO() bool {
	_, err := exec.Command("ls", "/sys/class/gpio").Output()
	return err == nil
}

// checkCamera checks if camera is available
func (hm *HardwareModule) checkCamera() bool {
	_, err := exec.Command("ls", "/dev/video0").Output()
	return err == nil
}

// checkAudio checks if audio is available
func (hm *HardwareModule) checkAudio() bool {
	_, err := exec.Command("arecord", "-l").Output()
	return err == nil
}

// checkSensors checks if sensors are available
func (hm *HardwareModule) checkSensors() bool {
	_, err := exec.Command("ls", "/sys/class/i2c-dev").Output()
	return err == nil
}

// checkIRBlaster checks if IR blaster is available
func (hm *HardwareModule) checkIRBlaster() bool {
	_, err := exec.Command("ls", "/sys/class/leds/led:ir").Output()
	return err == nil
}

// CameraDetectionScan performs camera detection scan
func (hm *HardwareModule) CameraDetectionScan() error {
	fmt.Printf("[HARDWARE] Starting camera detection scan\n")
	
	// IR reflection detection
	go hm.irReflectionScan()
	
	// Lens detection using camera flash
	go hm.lensDetectionScan()
	
	// RF camera detection
	go hm.rfCameraDetection()
	
	return nil
}

// irReflectionScan scans for IR reflections from camera lenses
func (hm *HardwareModule) irReflectionScan() {
	if !hm.irBlasterAvailable {
		fmt.Printf("[HARDWARE] IR blaster not available for reflection scan\n")
		return
	}
	
	fmt.Printf("[HARDWARE] Performing IR reflection scan\n")
	
	// Pulse IR and look for reflections
	for i := 0; i < 10; i++ {
		// Turn on IR
		exec.Command("echo", "255", ">", "/sys/class/leds/led:ir/brightness").Run()
		time.Sleep(100 * time.Millisecond)
		
		// Capture image and analyze for reflections
		if hm.cameraAvailable {
			hm.captureAndAnalyze()
		}
		
		// Turn off IR
		exec.Command("echo", "0", ">", "/sys/class/leds/led:ir/brightness").Run()
		time.Sleep(100 * time.Millisecond)
	}
}

// lensDetectionScan uses visible light to detect camera lenses
func (hm *HardwareModule) lensDetectionScan() {
	if !hm.cameraAvailable {
		fmt.Printf("[HARDWARE] Camera not available for lens detection\n")
		return
	}
	
	fmt.Printf("[HARDWARE] Performing lens detection scan\n")
	
	// Use camera flash to look for lens reflections
	for i := 0; i < 5; i++ {
		// Flash on
		exec.Command("su", "-c", "echo 1 > /sys/class/leds/led:flash_torch/brightness").Run()
		hm.captureAndAnalyze()
		
		// Flash off
		exec.Command("su", "-c", "echo 0 > /sys/class/leds/led:flash_torch/brightness").Run()
		time.Sleep(500 * time.Millisecond)
	}
}

// rfCameraDetection detects wireless cameras via RF signatures
func (hm *HardwareModule) rfCameraDetection() {
	fmt.Printf("[HARDWARE] RF camera detection\n")
	
	// Common camera frequencies
	frequencies := []string{"2.4GHz", "5.8GHz"}
	
	for range frequencies {
		// Use RTL-SDR if available
		cmd := exec.Command("rtl_power", "-f", "2400M:2500M:1M", "-i", "1", "-1", "/tmp/camera_scan.csv")
		cmd.Run()
	}
}

// captureAndAnalyze captures image and analyzes for reflections
func (hm *HardwareModule) captureAndAnalyze() {
	timestamp := time.Now().Unix()
	filename := fmt.Sprintf("/tmp/camera_scan_%d.jpg", timestamp)
	
	// Capture image
	cmd := exec.Command("fswebcam", "-r", "640x480", "--no-banner", filename)
	if err := cmd.Run(); err == nil {
		// Analyze for bright spots that could be lens reflections
		hm.analyzeImageForReflections(filename)
	}
}

// analyzeImageForReflections analyzes image for potential camera lens reflections
func (hm *HardwareModule) analyzeImageForReflections(filename string) {
	// This would use image processing to detect bright spots
	// For now, just log the analysis
	fmt.Printf("[HARDWARE] Analyzing %s for lens reflections\n", filename)
	
	// Could use imagemagick or similar for analysis
	cmd := exec.Command("identify", "-verbose", filename)
	output, err := cmd.Output()
	if err == nil {
		// Look for bright spots in image statistics
		if strings.Contains(string(output), "mean:") {
			fmt.Printf("[HARDWARE] Image analysis completed\n")
		}
	}
}

// AudioSurveillanceScan performs audio surveillance detection
func (hm *HardwareModule) AudioSurveillanceScan() error {
	fmt.Printf("[HARDWARE] Starting audio surveillance scan\n")
	
	// Ultrasonic beacon detection
	go hm.ultrasonicDetection()
	
	// Audio frequency analysis
	go hm.audioFrequencyAnalysis()
	
	// Voice activation detection
	go hm.voiceActivationDetection()
	
	return nil
}

// ultrasonicDetection detects ultrasonic beacons used for tracking
func (hm *HardwareModule) ultrasonicDetection() {
	if !hm.audioAvailable {
		fmt.Printf("[HARDWARE] Audio not available for ultrasonic detection\n")
		return
	}
	
	fmt.Printf("[HARDWARE] Performing ultrasonic detection\n")
	
	// Record high frequency audio
	cmd := exec.Command("timeout", "30", "arecord",
		"-f", "S16_LE",
		"-r", "96000", // High sample rate for ultrasonics
		"-c", "1",
		"/tmp/ultrasonic_scan.wav")
	
	if err := cmd.Run(); err == nil {
		// Analyze for ultrasonic patterns
		hm.analyzeUltrasonicAudio("/tmp/ultrasonic_scan.wav")
	}
}

// audioFrequencyAnalysis analyzes audio spectrum for surveillance devices
func (hm *HardwareModule) audioFrequencyAnalysis() {
	fmt.Printf("[HARDWARE] Audio frequency analysis\n")
	
	// Record ambient audio
	cmd := exec.Command("timeout", "10", "arecord",
		"-f", "S16_LE",
		"-r", "44100",
		"-c", "2",
		"/tmp/ambient_audio.wav")
	
	if err := cmd.Run(); err == nil {
		// Analyze frequency spectrum
		hm.analyzeAudioSpectrum("/tmp/ambient_audio.wav")
	}
}

// voiceActivationDetection detects voice-activated devices
func (hm *HardwareModule) voiceActivationDetection() {
	fmt.Printf("[HARDWARE] Voice activation detection\n")
	
	// Generate test sounds and monitor for responses
	testWords := []string{"Alexa", "Google", "Siri", "Hey"}
	
	for _, word := range testWords {
		// Play test word
		cmd := exec.Command("espeak", word)
		cmd.Run()
		
		// Monitor for network activity or RF responses
		time.Sleep(2 * time.Second)
	}
}

// analyzeUltrasonicAudio analyzes audio for ultrasonic patterns
func (hm *HardwareModule) analyzeUltrasonicAudio(filename string) {
	fmt.Printf("[HARDWARE] Analyzing ultrasonic audio: %s\n", filename)
	
	// Use sox or similar to analyze frequency content
	cmd := exec.Command("sox", filename, "-n", "stat")
	output, err := cmd.Output()
	if err == nil {
		if strings.Contains(string(output), "Maximum amplitude") {
			fmt.Printf("[HARDWARE] Ultrasonic analysis completed\n")
		}
	}
}

// analyzeAudioSpectrum analyzes audio spectrum
func (hm *HardwareModule) analyzeAudioSpectrum(filename string) {
	fmt.Printf("[HARDWARE] Analyzing audio spectrum: %s\n", filename)
	
	// FFT analysis would go here
	// For now, just basic analysis
	cmd := exec.Command("sox", filename, "-n", "spectrogram")
	cmd.Run()
}

// HardwareSecurityScan performs hardware security testing
func (hm *HardwareModule) HardwareSecurityScan() error {
	fmt.Printf("[HARDWARE] Starting hardware security scan\n")
	
	// GPIO scanning
	go hm.gpioSecurityScan()
	
	// I2C/SPI scanning
	go hm.busSecurityScan()
	
	// USB security scanning
	go hm.usbSecurityScan()
	
	// UART detection
	go hm.uartDetection()
	
	return nil
}

// gpioSecurityScan scans GPIO pins for security issues
func (hm *HardwareModule) gpioSecurityScan() {
	if !hm.gpioAvailable {
		fmt.Printf("[HARDWARE] GPIO not available\n")
		return
	}
	
	fmt.Printf("[HARDWARE] GPIO security scan\n")
	
	// Scan GPIO pins
	for i := 0; i < 40; i++ {
		pinPath := fmt.Sprintf("/sys/class/gpio/gpio%d", i)
		if _, err := exec.Command("ls", pinPath).Output(); err == nil {
			// Check pin configuration
			hm.checkGPIOPin(i)
		}
	}
}

// checkGPIOPin checks individual GPIO pin security
func (hm *HardwareModule) checkGPIOPin(pin int) {
	// Read pin direction
	dirPath := fmt.Sprintf("/sys/class/gpio/gpio%d/direction", pin)
	if output, err := exec.Command("cat", dirPath).Output(); err == nil {
		direction := strings.TrimSpace(string(output))
		
		// Read pin value
		valuePath := fmt.Sprintf("/sys/class/gpio/gpio%d/value", pin)
		if valueOutput, err := exec.Command("cat", valuePath).Output(); err == nil {
			value := strings.TrimSpace(string(valueOutput))
			fmt.Printf("[HARDWARE] GPIO%d: direction=%s, value=%s\n", pin, direction, value)
		}
	}
}

// busSecurityScan scans I2C/SPI buses
func (hm *HardwareModule) busSecurityScan() {
	fmt.Printf("[HARDWARE] Bus security scan\n")
	
	// I2C device detection
	cmd := exec.Command("i2cdetect", "-y", "1")
	if output, err := cmd.Output(); err == nil {
		fmt.Printf("[HARDWARE] I2C devices detected:\n%s\n", string(output))
	}
	
	// SPI device scanning would go here
}

// usbSecurityScan scans USB for security issues
func (hm *HardwareModule) usbSecurityScan() {
	fmt.Printf("[HARDWARE] USB security scan\n")
	
	// List USB devices
	cmd := exec.Command("lsusb")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "Bus") {
				hm.analyzeUSBDevice(line)
			}
		}
	}
}

// analyzeUSBDevice analyzes individual USB device
func (hm *HardwareModule) analyzeUSBDevice(deviceLine string) {
	// Extract device info and check for suspicious devices
	if strings.Contains(deviceLine, "HID") {
		fmt.Printf("[HARDWARE] HID device detected: %s\n", deviceLine)
	}
	if strings.Contains(deviceLine, "Mass Storage") {
		fmt.Printf("[HARDWARE] Mass storage device detected: %s\n", deviceLine)
	}
}

// uartDetection detects UART interfaces
func (hm *HardwareModule) uartDetection() {
	fmt.Printf("[HARDWARE] UART detection\n")
	
	// Scan common UART pins with GPIO
	uartPins := []int{14, 15, 16, 17} // Common UART pins on RPi
	
	for _, pin := range uartPins {
		hm.probeUARTPin(pin)
	}
}

// probeUARTPin probes pin for UART activity
func (hm *HardwareModule) probeUARTPin(pin int) {
	fmt.Printf("[HARDWARE] Probing GPIO%d for UART activity\n", pin)
	
	// Monitor pin for serial activity patterns
	// This would require more sophisticated logic
}

// IRJam performs IR jamming
func (hm *HardwareModule) IRJam(params map[string]interface{}) (bool, error) {
	if !hm.irBlasterAvailable {
		return false, fmt.Errorf("IR blaster not available")
	}
	
	fmt.Printf("[HARDWARE] Starting IR jamming\n")
	
	// Get frequency parameter
	_, ok := params["frequency"].(string)
	if !ok {
		// Use default IR frequency
	}
	
	duration := 30 * time.Second // Default duration
	if d, ok := params["duration"].(string); ok {
		if parsed, err := time.ParseDuration(d); err == nil {
			duration = parsed
		}
	}
	
	// Start IR strobing
	go hm.irStrobing(duration)
	
	return true, nil
}

// irStrobing performs IR LED strobing to disrupt cameras
func (hm *HardwareModule) irStrobing(duration time.Duration) {
	fmt.Printf("[HARDWARE] IR strobing for %s\n", duration)
	
	end := time.Now().Add(duration)
	for time.Now().Before(end) {
		// Turn on IR LEDs at maximum brightness
		exec.Command("echo", "255", ">", "/sys/class/leds/led:ir/brightness").Run()
		time.Sleep(10 * time.Millisecond)
		
		// Turn off IR LEDs
		exec.Command("echo", "0", ">", "/sys/class/leds/led:ir/brightness").Run()
		time.Sleep(10 * time.Millisecond)
	}
}

// GetHardwareStatus returns current hardware status
func (hm *HardwareModule) GetHardwareStatus() HardwareState {
	return HardwareState{
		SDRDevices:      hm.getSDRDevices(),
		WiFiAdapters:    hm.getWiFiAdapters(),
		BluetoothRadios: hm.getBluetoothRadios(),
		USBDevices:      hm.getUSBDevices(),
		IRBlasters:      hm.getIRBlasters(),
	}
}

// getSDRDevices gets available SDR devices
func (hm *HardwareModule) getSDRDevices() []SDRDevice {
	devices := make([]SDRDevice, 0)
	
	// Check for RTL-SDR
	if cmd := exec.Command("rtl_test", "-t"); cmd.Run() == nil {
		devices = append(devices, SDRDevice{
			ID:        "rtlsdr_0",
			Type:      "rtlsdr",
			Name:      "RTL-SDR",
			Connected: true,
		})
	}
	
	// Check for HackRF
	if cmd := exec.Command("hackrf_info"); cmd.Run() == nil {
		devices = append(devices, SDRDevice{
			ID:        "hackrf_0",
			Type:      "hackrf",
			Name:      "HackRF One",
			Connected: true,
		})
	}
	
	return devices
}

// getWiFiAdapters gets available WiFi adapters
func (hm *HardwareModule) getWiFiAdapters() []WiFiAdapter {
	adapters := make([]WiFiAdapter, 0)
	
	cmd := exec.Command("iwconfig")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "IEEE 802.11") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					adapters = append(adapters, WiFiAdapter{
						ID:        fmt.Sprintf("wifi_%s", parts[0]),
						Interface: parts[0],
						Connected: true,
					})
				}
			}
		}
	}
	
	return adapters
}

// getBluetoothRadios gets available Bluetooth radios
func (hm *HardwareModule) getBluetoothRadios() []BluetoothRadio {
	radios := make([]BluetoothRadio, 0)
	
	cmd := exec.Command("hciconfig")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "hci") && strings.Contains(line, ":") {
				parts := strings.Fields(line)
				if len(parts) > 0 {
					hciInterface := strings.TrimSuffix(parts[0], ":")
					radios = append(radios, BluetoothRadio{
						ID:        fmt.Sprintf("bt_%s", hciInterface),
						Interface: hciInterface,
						Connected: true,
					})
				}
			}
		}
	}
	
	return radios
}

// getUSBDevices gets available USB devices
func (hm *HardwareModule) getUSBDevices() []USBDevice {
	devices := make([]USBDevice, 0)
	
	cmd := exec.Command("lsusb")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for i, line := range lines {
			if strings.Contains(line, "Bus") {
				devices = append(devices, USBDevice{
					ID:          fmt.Sprintf("usb_%d", i),
					Description: line,
					Connected:   true,
				})
			}
		}
	}
	
	return devices
}

// getIRBlasters gets available IR blasters
func (hm *HardwareModule) getIRBlasters() []IRBlaster {
	blasters := make([]IRBlaster, 0)
	
	if hm.irBlasterAvailable {
		blasters = append(blasters, IRBlaster{
			ID:        "ir_0",
			Interface: "/sys/class/leds/led:ir",
			Connected: true,
		})
	}
	
	return blasters
}
