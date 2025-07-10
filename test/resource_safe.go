package test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ResourceSafeTester manages resource-safe testing
type ResourceSafeTester struct {
	testResults    map[string]interface{}
	activeTests    []*exec.Cmd
	emilyBin       string
	maxCPUPercent  float64
	maxMemoryMB    int64
	running        bool
	mu             sync.Mutex
	testOutput     []string
}

// SystemInfo holds system resource information
type SystemInfo struct {
	CPUCount    int
	TotalMemory int64 // in MB
	UsedMemory  int64 // in MB
	DiskUsage   float64 // percentage
}

// NewResourceSafeTester creates a new resource-safe tester instance
func NewResourceSafeTester() *ResourceSafeTester {
	return &ResourceSafeTester{
		testResults:   make(map[string]interface{}),
		activeTests:   make([]*exec.Cmd, 0),
		emilyBin:      "./bin/emily",
		maxCPUPercent: 50.0, // Limit CPU usage to 50%
		maxMemoryMB:   512,  // Limit memory to 512MB
		running:       true,
	}
}

func (rst *ResourceSafeTester) log(message string, level string) {
	timestamp := time.Now().Format("15:04:05")
	logLine := fmt.Sprintf("[%s] %s: %s", timestamp, level, message)
	fmt.Println(logLine)
	rst.testOutput = append(rst.testOutput, logLine)
}

// GetSystemInfo retrieves current system information
func (rst *ResourceSafeTester) GetSystemInfo() SystemInfo {
	info := SystemInfo{
		CPUCount: runtime.NumCPU(),
	}

	// Get memory info using runtime stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	info.TotalMemory = int64(m.Sys / 1024 / 1024) // Convert to MB
	info.UsedMemory = int64(m.Alloc / 1024 / 1024) // Convert to MB

	// Get disk usage using df command
	cmd := exec.Command("df", "/")
	if stdout, err := cmd.Output(); err == nil {
		lines := strings.Split(string(stdout), "\n")
		if len(lines) > 1 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 5 {
				usage := strings.TrimSuffix(fields[4], "%")
				if val, err := fmt.Sscanf(usage, "%f", &info.DiskUsage); err == nil && val == 1 {
					// Successfully parsed disk usage
				}
			}
		}
	}

	return info
}

// CheckResources checks if system resources are within safe limits
func (rst *ResourceSafeTester) CheckResources() bool {
	info := rst.GetSystemInfo()

	// Check memory usage (basic check using available system info)
	memoryUsagePercent := float64(info.UsedMemory) / float64(info.TotalMemory) * 100
	if memoryUsagePercent > 80 {
		rst.log(fmt.Sprintf("High memory usage detected: %.1f%%. Pausing tests...", memoryUsagePercent), "WARN")
		time.Sleep(5 * time.Second)
		return false
	}

	// Check available disk space
	if info.DiskUsage > 90 {
		rst.log(fmt.Sprintf("Low disk space: %.1f%% used. Stopping tests...", info.DiskUsage), "ERROR")
		return false
	}

	return true
}

// CreateTestEnvironment sets up minimal test environment
func (rst *ResourceSafeTester) CreateTestEnvironment() {
	rst.log("Setting up minimal test environment...", "INFO")

	// Only enable services if they're not already running
	// Check if NetworkManager is running
	cmd := exec.Command("systemctl", "is-active", "NetworkManager")
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("sudo", "systemctl", "start", "NetworkManager")
		if err := cmd.Run(); err != nil {
			rst.log(fmt.Sprintf("Service setup warning: %v", err), "WARN")
		} else {
			rst.log("NetworkManager started", "INFO")
		}
	} else {
		rst.log("NetworkManager already running", "INFO")
	}
}

// TestBasicDetection tests basic detection without intensive operations
func (rst *ResourceSafeTester) TestBasicDetection() {
	rst.log("Testing basic detection (30 seconds)...", "INFO")

	if !rst.CheckResources() {
		rst.log("Skipping detection test due to resource constraints", "WARN")
		return
	}

	// Run emily for only 30 seconds instead of 2 minutes
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, rst.emilyBin, "scan", "--quiet")
	
	stdout, _, err := rst.runCommandWithOutput(cmd)
	if err != nil && ctx.Err() != context.DeadlineExceeded {
		rst.log(fmt.Sprintf("Basic detection test failed: %v", err), "ERROR")
		return
	}

	// Analyze results
	detectedWiFi := strings.Count(stdout, "WiFi device") + strings.Count(stdout, "wifi")
	detectedBluetooth := strings.Count(stdout, "Bluetooth device") + strings.Count(stdout, "bluetooth")

	rst.testResults["wifi_detection"] = detectedWiFi
	rst.testResults["bluetooth_detection"] = detectedBluetooth

	rst.log(fmt.Sprintf("Basic detection: %d WiFi, %d Bluetooth", detectedWiFi, detectedBluetooth), "INFO")
}

func (rst *ResourceSafeTester) runCommandWithOutput(cmd *exec.Cmd) (string, string, error) {
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// TestConfigValidation tests configuration validation
func (rst *ResourceSafeTester) TestConfigValidation() {
	rst.log("Testing configuration validation...", "INFO")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, rst.emilyBin, "config", "--help")
	_, stderr, err := rst.runCommandWithOutput(cmd)

	if err == nil {
		rst.testResults["config_valid"] = true
		rst.log("Configuration validation passed", "INFO")
	} else {
		rst.testResults["config_valid"] = false
		rst.log(fmt.Sprintf("Configuration validation failed: %s", stderr), "ERROR")
	}
}

// TestToolAvailability tests if required tools are available
func (rst *ResourceSafeTester) TestToolAvailability() {
	rst.log("Testing tool availability...", "INFO")

	tools := map[string][]string{
		"system":   {"systemctl", "ps", "netstat"},
		"network":  {"iwconfig", "rfkill", "bluetoothctl"},
		"optional": {"aircrack-ng", "hcxdumptool", "tcpdump"},
	}

	results := make(map[string]float64)
	for category, toolList := range tools {
		available := 0
		for _, tool := range toolList {
			cmd := exec.Command("which", tool)
			if err := cmd.Run(); err == nil {
				available++
			}
		}

		results[category] = float64(available) / float64(len(toolList))
		rst.log(fmt.Sprintf("%s tools: %d/%d available", strings.Title(category), available, len(toolList)), "INFO")
	}

	rst.testResults["tool_availability"] = results
}

// TestFilePermissions tests file system permissions
func (rst *ResourceSafeTester) TestFilePermissions() {
	rst.log("Testing file permissions...", "INFO")

	// Check if main binary is executable
	emilyBinary := "./bin/emily"
	if stat, err := os.Stat(emilyBinary); err == nil && stat.Mode().IsRegular() {
		permissionsOk := stat.Mode()&0111 != 0
		rst.testResults["emily_executable"] = permissionsOk
		rst.log(fmt.Sprintf("EMILY binary executable: %v", permissionsOk), "INFO")
	} else {
		rst.testResults["emily_executable"] = false
		rst.log("EMILY binary not found", "ERROR")
	}

	// Check if we can write to evidence directory
	evidenceDir := "evidence"
	if err := os.MkdirAll(evidenceDir, 0755); err != nil {
		rst.testResults["evidence_writable"] = false
		rst.log("Evidence directory not writable", "ERROR")
		return
	}

	testFile := filepath.Join(evidenceDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		rst.testResults["evidence_writable"] = false
		rst.log("Evidence directory not writable", "ERROR")
	} else {
		os.Remove(testFile) // Clean up
		rst.testResults["evidence_writable"] = true
		rst.log("Evidence directory writable: True", "INFO")
	}
}

// TestNetworkInterfaces tests network interface availability
func (rst *ResourceSafeTester) TestNetworkInterfaces() {
	rst.log("Testing network interfaces...", "INFO")

	// Check wireless interfaces
	cmd := exec.Command("iwconfig")
	stdout, _, _ := rst.runCommandWithOutput(cmd)

	wirelessInterfaces := 0
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "IEEE 802.11") {
			wirelessInterfaces++
		}
	}

	rst.testResults["wireless_interfaces"] = wirelessInterfaces
	rst.log(fmt.Sprintf("Wireless interfaces found: %d", wirelessInterfaces), "INFO")

	// Check Bluetooth
	cmd = exec.Command("hciconfig")
	stdout, _, _ = rst.runCommandWithOutput(cmd)

	bluetoothAvailable := strings.Contains(stdout, "hci")
	rst.testResults["bluetooth_available"] = bluetoothAvailable
	rst.log(fmt.Sprintf("Bluetooth available: %v", bluetoothAvailable), "INFO")
}

// Cleanup cleans up test environment
func (rst *ResourceSafeTester) Cleanup() {
	rst.log("Cleaning up test environment...", "INFO")

	rst.mu.Lock()
	defer rst.mu.Unlock()

	// Terminate any active processes
	for _, process := range rst.activeTests {
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

	// Clean up any test files
	testEvidence := filepath.Join("evidence", "test.txt")
	os.Remove(testEvidence)
}

// GenerateReport generates test report
func (rst *ResourceSafeTester) GenerateReport() {
	rst.log("\n"+strings.Repeat("=", 50), "INFO")
	rst.log("EMILY RESOURCE-SAFE TEST REPORT (Go Version)", "INFO")
	rst.log(strings.Repeat("=", 50), "INFO")

	// System info
	info := rst.GetSystemInfo()
	rst.log(fmt.Sprintf("System: %d CPUs, %dMB RAM", info.CPUCount, info.TotalMemory), "INFO")

	// Test results
	for test, result := range rst.testResults {
		if resultMap, ok := result.(map[string]float64); ok {
			rst.log(fmt.Sprintf("%s:", strings.ToUpper(test)), "INFO")
			for key, value := range resultMap {
				rst.log(fmt.Sprintf("  %s: %.2f", key, value), "INFO")
			}
		} else {
			rst.log(fmt.Sprintf("%s: %v", strings.ToUpper(test), result), "INFO")
		}
	}

	// Calculate health score
	var scores []float64

	// Basic functionality
	if configValid, ok := rst.testResults["config_valid"].(bool); ok && configValid {
		scores = append(scores, 1.0)
	} else {
		scores = append(scores, 0.0)
	}

	if emilyExecutable, ok := rst.testResults["emily_executable"].(bool); ok && emilyExecutable {
		scores = append(scores, 1.0)
	} else {
		scores = append(scores, 0.0)
	}

	// Tool availability
	if toolAvailability, ok := rst.testResults["tool_availability"].(map[string]float64); ok {
		totalScore := 0.0
		for _, score := range toolAvailability {
			totalScore += score
		}
		if len(toolAvailability) > 0 {
			scores = append(scores, totalScore/float64(len(toolAvailability)))
		}
	}

	// Network capabilities
	if wirelessInterfaces, ok := rst.testResults["wireless_interfaces"].(int); ok && wirelessInterfaces > 0 {
		scores = append(scores, 1.0)
	} else {
		scores = append(scores, 0.5)
	}

	if bluetoothAvailable, ok := rst.testResults["bluetooth_available"].(bool); ok && bluetoothAvailable {
		scores = append(scores, 1.0)
	} else {
		scores = append(scores, 0.5)
	}

	// Detection capabilities
	wifiDetected, wifiOk := rst.testResults["wifi_detection"].(int)
	bluetoothDetected, bluetoothOk := rst.testResults["bluetooth_detection"].(int)
	if (wifiOk && wifiDetected > 0) || (bluetoothOk && bluetoothDetected > 0) {
		scores = append(scores, 1.0)
	} else {
		scores = append(scores, 0.3) // Might be due to no devices around
	}

	if len(scores) > 0 {
		healthScore := 0.0
		for _, score := range scores {
			healthScore += score
		}
		healthScore /= float64(len(scores))

		rst.log(fmt.Sprintf("\nOVERALL HEALTH SCORE: %.2f/1.00", healthScore), "INFO")

		if healthScore >= 0.8 {
			rst.log("✅ EMILY is in EXCELLENT condition", "SUCCESS")
		} else if healthScore >= 0.6 {
			rst.log("⚠️  EMILY is in GOOD condition", "SUCCESS")
		} else if healthScore >= 0.4 {
			rst.log("⚠️  EMILY needs minor improvements", "WARN")
		} else {
			rst.log("❌ EMILY needs attention", "ERROR")
		}
	} else {
		rst.log("❌ Unable to calculate health score", "ERROR")
	}
}

// RunSafeTests runs resource-safe test suite
func (rst *ResourceSafeTester) RunSafeTests() {
	rst.log("Starting EMILY Resource-Safe Test Suite (Go Version)", "INFO")
	rst.log(strings.Repeat("=", 50), "INFO")

	// Initial resource check
	if !rst.CheckResources() {
		rst.log("System resources too high to run tests safely", "ERROR")
		return
	}

	defer rst.Cleanup()

	rst.CreateTestEnvironment()

	// Run lightweight tests first
	rst.TestConfigValidation()
	rst.TestFilePermissions()
	rst.TestToolAvailability()
	rst.TestNetworkInterfaces()

	// Only run detection test if resources are still good
	if rst.CheckResources() && rst.running {
		rst.TestBasicDetection()
	} else {
		rst.log("Skipping detection test due to resource constraints", "WARN")
	}

	rst.GenerateReport()
}

// TestResourceSafe is the main test function for resource-safe testing
func TestResourceSafe(t *testing.T) {
	// Check if emily binary exists
	emilyBin := "./bin/emily"
	if _, err := os.Stat(emilyBin); err != nil {
		t.Skipf("EMILY binary not found at %s", emilyBin)
		return
	}

	tester := NewResourceSafeTester()
	tester.RunSafeTests()
}

// TestResourceSafeComponents tests individual components safely
func TestResourceSafeComponents(t *testing.T) {
	tester := NewResourceSafeTester()

	t.Run("Config Validation", func(t *testing.T) {
		tester.TestConfigValidation()
		
		if configValid, ok := tester.testResults["config_valid"].(bool); ok {
			if !configValid {
				t.Error("Configuration validation failed")
			}
		} else {
			t.Error("Config validation test did not complete")
		}
	})

	t.Run("File Permissions", func(t *testing.T) {
		tester.TestFilePermissions()
		
		if executable, ok := tester.testResults["emily_executable"].(bool); ok {
			if !executable {
				t.Error("EMILY binary is not executable")
			}
		}

		if writable, ok := tester.testResults["evidence_writable"].(bool); ok {
			if !writable {
				t.Error("Evidence directory is not writable")
			}
		}
	})

	t.Run("Tool Availability", func(t *testing.T) {
		tester.TestToolAvailability()
		
		if toolAvailability, ok := tester.testResults["tool_availability"].(map[string]float64); ok {
			systemTools := toolAvailability["system"]
			if systemTools < 0.5 {
				t.Errorf("Too few system tools available: %.2f", systemTools)
			}
			t.Logf("System tools: %.2f, Network tools: %.2f, Optional tools: %.2f", 
				toolAvailability["system"], toolAvailability["network"], toolAvailability["optional"])
		}
	})

	t.Run("Network Interfaces", func(t *testing.T) {
		tester.TestNetworkInterfaces()
		
		wirelessInterfaces, wifiOk := tester.testResults["wireless_interfaces"].(int)
		bluetoothAvailable, btOk := tester.testResults["bluetooth_available"].(bool)
		
		if wifiOk {
			t.Logf("Wireless interfaces: %d", wirelessInterfaces)
		}
		
		if btOk {
			t.Logf("Bluetooth available: %v", bluetoothAvailable)
		}
		
		if (!wifiOk || wirelessInterfaces == 0) && (!btOk || !bluetoothAvailable) {
			t.Log("Warning: No wireless interfaces or Bluetooth detected")
		}
	})

	t.Run("Basic Detection", func(t *testing.T) {
		if !tester.CheckResources() {
			t.Skip("Skipping detection test due to resource constraints")
			return
		}
		
		tester.TestBasicDetection()
		
		wifiDetection, wifiOk := tester.testResults["wifi_detection"].(int)
		bluetoothDetection, bluetoothOk := tester.testResults["bluetooth_detection"].(int)
		
		if wifiOk {
			t.Logf("WiFi devices detected: %d", wifiDetection)
		}
		
		if bluetoothOk {
			t.Logf("Bluetooth devices detected: %d", bluetoothDetection)
		}
	})
}
