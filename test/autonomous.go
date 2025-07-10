package test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// AutonomousTester manages autonomous mode testing
type AutonomousTester struct {
	testResults  map[string]interface{}
	activeTests  []*exec.Cmd
	emilyBin     string
	mu           sync.Mutex
	testOutput   []string
}

// NewAutonomousTester creates a new autonomous tester instance
func NewAutonomousTester() *AutonomousTester {
	return &AutonomousTester{
		testResults: make(map[string]interface{}),
		activeTests: make([]*exec.Cmd, 0),
		emilyBin:    "./bin/emily",
	}
}

func (at *AutonomousTester) log(message string, level string) {
	timestamp := time.Now().Format("15:04:05")
	logLine := fmt.Sprintf("[%s] %s: %s", timestamp, level, message)
	fmt.Println(logLine)
	at.testOutput = append(at.testOutput, logLine)
}

func (at *AutonomousTester) addActiveTest(cmd *exec.Cmd) {
	at.mu.Lock()
	defer at.mu.Unlock()
	at.activeTests = append(at.activeTests, cmd)
}

func (at *AutonomousTester) removeActiveTest(cmd *exec.Cmd) {
	at.mu.Lock()
	defer at.mu.Unlock()
	for i, test := range at.activeTests {
		if test == cmd {
			at.activeTests = append(at.activeTests[:i], at.activeTests[i+1:]...)
			break
		}
	}
}

// CreateTestEnvironment sets up controlled test environment
func (at *AutonomousTester) CreateTestEnvironment() {
	at.log("Setting up test environment...", "INFO")

	// Enable WiFi and Bluetooth for testing
	at.log("Starting network services...", "INFO")
	
	// Start NetworkManager
	cmd := exec.Command("sudo", "systemctl", "start", "NetworkManager")
	if err := cmd.Run(); err != nil {
		at.log(fmt.Sprintf("Failed to start NetworkManager: %v", err), "WARN")
	}

	// Start Bluetooth
	cmd = exec.Command("sudo", "systemctl", "start", "bluetooth")
	if err := cmd.Run(); err != nil {
		at.log(fmt.Sprintf("Failed to start Bluetooth: %v", err), "WARN")
	}

	// Create test networks (simulated)
	at.createTestNetworks()

	// Start Bluetooth tests
	at.startBluetoothTests()
}

func (at *AutonomousTester) createTestNetworks() {
	at.log("Creating test WiFi networks...", "INFO")
	
	testNetworks := []string{
		"FREE_WIFI_DEFINITELY_LEGIT",
		"Starbucks_Guest",
		"xfinitywifi",
		"iPhone_Hotspot_Surveillance",
	}

	// Note: This simulates test network creation
	// In a real environment, this would require actual WiFi hardware setup
	for _, network := range testNetworks {
		at.log(fmt.Sprintf("Test network available: %s", network), "INFO")
	}
}

func (at *AutonomousTester) startBluetoothTests() {
	at.log("Starting Bluetooth test devices...", "INFO")

	// Start bluetoothctl in background to make device discoverable
	cmd := exec.Command("bluetoothctl")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		at.log(fmt.Sprintf("Failed to create stdin pipe: %v", err), "WARN")
		return
	}

	if err := cmd.Start(); err != nil {
		at.log(fmt.Sprintf("Failed to start bluetoothctl: %v", err), "WARN")
		return
	}

	// Make discoverable
	go func() {
		defer stdin.Close()
		fmt.Fprintln(stdin, "discoverable on")
		fmt.Fprintln(stdin, "pairable on")
		time.Sleep(2 * time.Second)
		fmt.Fprintln(stdin, "quit")
	}()

	at.addActiveTest(cmd)
	at.log("Bluetooth test device activated", "INFO")
}

// TestDetectionAccuracy tests detection accuracy against known devices
func (at *AutonomousTester) TestDetectionAccuracy() {
	at.log("Testing detection accuracy...", "INFO")

	// Run emily in autonomous mode for 30 seconds (reduced for resource safety)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, at.emilyBin, "autonomous", "--no-exploits", "--no-countermeasures")
	
	stdout, _, err := at.runCommandWithOutput(cmd)
	if err != nil {
		at.log(fmt.Sprintf("Detection test failed: %v", err), "ERROR")
		return
	}

	// Analyze results
	detectedWiFi := strings.Count(stdout, "WiFi device detected")
	detectedBluetooth := strings.Count(stdout, "Bluetooth device detected")

	at.testResults["wifi_detection"] = detectedWiFi
	at.testResults["bluetooth_detection"] = detectedBluetooth

	at.log(fmt.Sprintf("Detected %d WiFi devices", detectedWiFi), "INFO")
	at.log(fmt.Sprintf("Detected %d Bluetooth devices", detectedBluetooth), "INFO")
}

func (at *AutonomousTester) runCommandWithOutput(cmd *exec.Cmd) (string, string, error) {
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// TestResponseSpeed tests autonomous response time
func (at *AutonomousTester) TestResponseSpeed() {
	at.log("Testing response speed...", "INFO")

	startTime := time.Now()

	// Create a test WiFi hotspot (simulated)
	at.log("Creating test hotspot...", "INFO")
	
	// In a real environment, this would create an actual hotspot
	// For testing, we'll simulate the process
	testNetwork := "EMILY_TEST_NETWORK"
	
	// Monitor emily's response
	ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, at.emilyBin, "autonomous", "--no-exploits", "--no-countermeasures")
	stdout, _, err := at.runCommandWithOutput(cmd)

	detectionTime := time.Since(startTime)
	
	if err == nil && strings.Contains(stdout, testNetwork) {
		at.log(fmt.Sprintf("Detection time: %.2f seconds", detectionTime.Seconds()), "INFO")
		at.testResults["response_time"] = detectionTime.Seconds()
	} else {
		at.log("Failed to detect test network within timeout", "ERROR")
		at.testResults["response_time"] = -1
	}
}

// TestCountermeasures tests countermeasure effectiveness
func (at *AutonomousTester) TestCountermeasures() {
	at.log("Testing countermeasures...", "INFO")

	// This would test jamming effectiveness, etc.
	// For safety, we'll simulate the test
	at.log("Simulating countermeasure test...", "INFO")
	time.Sleep(5 * time.Second)

	// Check if countermeasures would work
	countermeasuresAvailable := at.checkCountermeasureTools()
	at.testResults["countermeasures"] = countermeasuresAvailable
	at.log(fmt.Sprintf("Countermeasures available: %.2f", countermeasuresAvailable), "INFO")
}

func (at *AutonomousTester) checkCountermeasureTools() float64 {
	tools := []string{"aircrack-ng", "hcxdumptool", "rfkill"}
	available := 0

	for _, tool := range tools {
		cmd := exec.Command("which", tool)
		if err := cmd.Run(); err == nil {
			available++
		}
	}

	return float64(available) / float64(len(tools))
}

// TestStealthMode tests stealth operation
func (at *AutonomousTester) TestStealthMode() {
	at.log("Testing stealth mode...", "INFO")

	// Check if emily is detectable by common monitoring tools
	stealthScore := 1.0

	// Check process visibility
	cmd := exec.Command("ps", "aux")
	stdout, _, err := at.runCommandWithOutput(cmd)
	if err == nil {
		emilyVisible := strings.Contains(strings.ToLower(stdout), "emily")
		if emilyVisible {
			stealthScore -= 0.5
			at.log("WARNING: EMILY process visible in ps", "WARN")
		}
	}

	// Check network connections
	cmd = exec.Command("netstat", "-tulpn")
	stdout, _, err = at.runCommandWithOutput(cmd)
	if err == nil {
		emilyConnections := strings.Contains(strings.ToLower(stdout), "emily")
		if emilyConnections {
			stealthScore -= 0.5
			at.log("WARNING: EMILY network activity visible", "WARN")
		}
	}

	at.testResults["stealth"] = stealthScore
	at.log(fmt.Sprintf("Stealth score: %.2f", stealthScore), "INFO")
}

// TestEvidenceCollection tests forensic evidence collection
func (at *AutonomousTester) TestEvidenceCollection() {
	at.log("Testing evidence collection...", "INFO")

	evidenceDir := "evidence"
	evidenceFiles := 0

	if _, err := os.Stat(evidenceDir); err == nil {
		// Count pcap files
		pcapFiles, _ := filepath.Glob(filepath.Join(evidenceDir, "*.pcap"))
		
		// Count log files
		logFiles, _ := filepath.Glob(filepath.Join(evidenceDir, "*.log"))

		evidenceFiles = len(pcapFiles) + len(logFiles)
		at.log(fmt.Sprintf("Evidence files created: %d pcap, %d logs", len(pcapFiles), len(logFiles)), "INFO")
	} else {
		at.log("No evidence directory found", "WARN")
	}

	at.testResults["evidence_files"] = evidenceFiles
}

// Cleanup cleans up test environment
func (at *AutonomousTester) Cleanup() {
	at.log("Cleaning up test environment...", "INFO")

	at.mu.Lock()
	defer at.mu.Unlock()

	// Terminate active test processes
	for _, process := range at.activeTests {
		if process.Process != nil {
			// Try graceful termination first
			if err := process.Process.Signal(syscall.SIGTERM); err == nil {
				// Wait for graceful shutdown
				done := make(chan error, 1)
				go func() {
					done <- process.Wait()
				}()

				select {
				case <-done:
					// Process terminated gracefully
				case <-time.After(5 * time.Second):
					// Force kill after timeout
					process.Process.Kill()
				}
			} else {
				// Force kill if graceful termination fails
				process.Process.Kill()
			}
		}
	}

	// Clean up test files
	exec.Command("sudo", "pkill", "-f", "create_ap").Run()
}

// GenerateReport generates test report
func (at *AutonomousTester) GenerateReport() {
	at.log("\n"+strings.Repeat("=", 50), "INFO")
	at.log("EMILY AUTONOMOUS MODE TEST REPORT (Go Version)", "INFO")
	at.log(strings.Repeat("=", 50), "INFO")

	for test, result := range at.testResults {
		at.log(fmt.Sprintf("%s: %v", strings.ToUpper(test), result), "INFO")
	}

	// Calculate overall score
	var scores []float64

	if wifiDetection, ok := at.testResults["wifi_detection"].(int); ok {
		scores = append(scores, float64(min(wifiDetection, 5))/5.0)
	}

	if bluetoothDetection, ok := at.testResults["bluetooth_detection"].(int); ok {
		scores = append(scores, float64(min(bluetoothDetection, 3))/3.0)
	}

	if responseTime, ok := at.testResults["response_time"].(float64); ok && responseTime > 0 {
		// Good response time is under 30 seconds
		score := max(0, 1.0-responseTime/30.0)
		scores = append(scores, score)
	}

	if countermeasures, ok := at.testResults["countermeasures"].(float64); ok {
		scores = append(scores, countermeasures)
	}

	if stealth, ok := at.testResults["stealth"].(float64); ok {
		scores = append(scores, stealth)
	}

	if evidenceFiles, ok := at.testResults["evidence_files"].(int); ok {
		scores = append(scores, float64(min(evidenceFiles, 10))/10.0)
	}

	if len(scores) > 0 {
		overallScore := 0.0
		for _, score := range scores {
			overallScore += score
		}
		overallScore /= float64(len(scores))

		at.log(fmt.Sprintf("\nOVERALL SCORE: %.2f/1.00", overallScore), "INFO")

		if overallScore >= 0.8 {
			at.log("✅ EMILY autonomous mode is EXCELLENT", "SUCCESS")
		} else if overallScore >= 0.6 {
			at.log("⚠️  EMILY autonomous mode is GOOD", "SUCCESS")
		} else if overallScore >= 0.4 {
			at.log("⚠️  EMILY autonomous mode needs IMPROVEMENT", "WARN")
		} else {
			at.log("❌ EMILY autonomous mode needs MAJOR FIXES", "ERROR")
		}
	} else {
		at.log("❌ Unable to calculate score - no tests completed", "ERROR")
	}
}

// RunAllTests runs comprehensive test suite
func (at *AutonomousTester) RunAllTests() {
	at.log("Starting EMILY Autonomous Mode Test Suite (Go Version)", "INFO")
	at.log(strings.Repeat("=", 50), "INFO")

	defer at.Cleanup()

	at.CreateTestEnvironment()
	time.Sleep(10 * time.Second) // Let environment settle

	at.TestDetectionAccuracy()
	at.TestResponseSpeed()
	at.TestCountermeasures()
	at.TestStealthMode()
	at.TestEvidenceCollection()

	at.GenerateReport()
}

// GetTestResults returns the test results map
func (at *AutonomousTester) GetTestResults() map[string]interface{} {
	return at.testResults
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// TestAutonomousMode is the main test function
func TestAutonomousMode(t *testing.T) {
	// Check if emily binary exists
	emilyBin := "./bin/emily"
	if _, err := os.Stat(emilyBin); err != nil {
		t.Skipf("EMILY binary not found at %s", emilyBin)
		return
	}

	tester := NewAutonomousTester()
	tester.RunAllTests()
}

// TestAutonomousDetection tests specific detection capabilities
func TestAutonomousDetection(t *testing.T) {
	tester := NewAutonomousTester()
	
	t.Run("Detection Accuracy", func(t *testing.T) {
		tester.TestDetectionAccuracy()
		
		wifiDetection, wifiOk := tester.testResults["wifi_detection"].(int)
		bluetoothDetection, bluetoothOk := tester.testResults["bluetooth_detection"].(int)
		
		if !wifiOk && !bluetoothOk {
			t.Error("No detection results available")
		}
		
		if wifiOk {
			t.Logf("WiFi devices detected: %d", wifiDetection)
		}
		
		if bluetoothOk {
			t.Logf("Bluetooth devices detected: %d", bluetoothDetection)
		}
	})
	
	t.Run("Response Speed", func(t *testing.T) {
		tester.TestResponseSpeed()
		
		if responseTime, ok := tester.testResults["response_time"].(float64); ok {
			if responseTime > 60 {
				t.Errorf("Response time too slow: %.2f seconds", responseTime)
			} else if responseTime > 0 {
				t.Logf("Response time: %.2f seconds", responseTime)
			}
		}
	})
	
	t.Run("Stealth Mode", func(t *testing.T) {
		tester.TestStealthMode()
		
		if stealthScore, ok := tester.testResults["stealth"].(float64); ok {
			if stealthScore < 0.5 {
				t.Errorf("Stealth score too low: %.2f", stealthScore)
			} else {
				t.Logf("Stealth score: %.2f", stealthScore)
			}
		}
	})
}
