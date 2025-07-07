//go:build linux
// +build linux

package scanner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/null/emily/internal/config"
)

// SignumScanner implements advanced memory initialization and signal analysis
// Based on SOPHIA's detection capabilities but enhanced for offensive operations
type SignumScanner struct {
	config       *config.Config
	running      bool
	memBaseline  map[string][]byte
	signalHashes map[string]string
	processMap   map[int]*ProcessInfo
}

// ProcessInfo holds detailed process information for memory analysis
type ProcessInfo struct {
	PID        int
	Name       string
	MemRegions []MemoryRegion
	Signals    []SignalInfo
	Baseline   []byte
}

// MemoryRegion represents a memory segment for analysis
type MemoryRegion struct {
	Start       uintptr
	End         uintptr
	Permissions string
	Path        string
	Content     []byte
	Hash        string
}

// SignalInfo captures signal intelligence data
type SignalInfo struct {
	Type      string
	Frequency float64
	Power     float64
	Timestamp time.Time
	Source    string
	Content   []byte
}

// NewSignumScanner creates a new advanced signum scanner
func NewSignumScanner(cfg *config.Config) *SignumScanner {
	return &SignumScanner{
		config:       cfg,
		memBaseline:  make(map[string][]byte),
		signalHashes: make(map[string]string),
		processMap:   make(map[int]*ProcessInfo),
	}
}

// Start initializes the signum scanner with memory baseline
func (s *SignumScanner) Start(ctx context.Context) error {
	s.running = true
	
	// Initialize memory baseline
	if err := s.initializeMemoryBaseline(); err != nil {
		return fmt.Errorf("failed to initialize memory baseline: %w", err)
	}
	
	// Start continuous monitoring
	go s.continuousMemoryMonitoring(ctx)
	go s.signalIntelligenceMonitoring(ctx)
	go s.processInjectionDetection(ctx)
	
	return nil
}

// Stop stops the signum scanner
func (s *SignumScanner) Stop() error {
	s.running = false
	return nil
}

// initializeMemoryBaseline creates a baseline of critical system memory regions
func (s *SignumScanner) initializeMemoryBaseline() error {
	// Read critical system files and memory regions
	criticalPaths := []string{
		"/proc/version",
		"/proc/cpuinfo", 
		"/proc/meminfo",
		"/proc/modules",
		"/proc/kallsyms",
		"/sys/devices/system/cpu/vulnerabilities/*",
	}
	
	for _, path := range criticalPaths {
		if strings.Contains(path, "*") {
			// Handle glob patterns
			matches, err := exec.Command("sh", "-c", fmt.Sprintf("ls %s 2>/dev/null", path)).Output()
			if err != nil {
				continue
			}
			for _, match := range strings.Split(strings.TrimSpace(string(matches)), "\n") {
				if match != "" {
					s.readAndHashFile(match)
				}
			}
		} else {
			s.readAndHashFile(path)
		}
	}
	
	// Initialize process memory baseline
	if err := s.scanProcessMemory(); err != nil {
		return fmt.Errorf("failed to scan process memory: %w", err)
	}
	
	return nil
}

// readAndHashFile reads a file and stores its hash for change detection
func (s *SignumScanner) readAndHashFile(path string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	
	hash := sha256.Sum256(content)
	s.memBaseline[path] = content
	s.signalHashes[path] = fmt.Sprintf("%x", hash)
}

// scanProcessMemory performs deep memory analysis of running processes
func (s *SignumScanner) scanProcessMemory() error {
	processes, err := s.getRunningProcesses()
	if err != nil {
		return err
	}
	
	for _, pid := range processes {
		if err := s.analyzeProcessMemory(pid); err != nil {
			// Log error but continue with other processes
			continue
		}
	}
	
	return nil
}

// getRunningProcesses returns list of running process PIDs
func (s *SignumScanner) getRunningProcesses() ([]int, error) {
	var pids []int
	
	files, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	
	for _, file := range files {
		if pid, err := strconv.Atoi(file.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	
	return pids, nil
}

// analyzeProcessMemory performs detailed memory analysis of a specific process
func (s *SignumScanner) analyzeProcessMemory(pid int) error {
	// Read process maps
	mapsContent, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return err
	}
	
	// Parse memory regions
	regions := s.parseMemoryMaps(string(mapsContent))
	
	// Read process name
	cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	name := strings.ReplaceAll(string(cmdline), "\x00", " ")
	if name == "" {
		comm, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		name = strings.TrimSpace(string(comm))
	}
	
	// Create process info
	procInfo := &ProcessInfo{
		PID:        pid,
		Name:       name,
		MemRegions: regions,
		Signals:    []SignalInfo{},
	}
	
	// Analyze memory for suspicious patterns
	s.detectMemoryAnomalies(procInfo)
	
	s.processMap[pid] = procInfo
	return nil
}

// parseMemoryMaps parses /proc/pid/maps content
func (s *SignumScanner) parseMemoryMaps(maps string) []MemoryRegion {
	var regions []MemoryRegion
	
	lines := strings.Split(maps, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		
		// Parse address range
		addrRange := strings.Split(parts[0], "-")
		if len(addrRange) != 2 {
			continue
		}
		
		start, err1 := strconv.ParseUint(addrRange[0], 16, 64)
		end, err2 := strconv.ParseUint(addrRange[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		
		region := MemoryRegion{
			Start:       uintptr(start),
			End:         uintptr(end),
			Permissions: parts[1],
		}
		
		if len(parts) > 5 {
			region.Path = strings.Join(parts[5:], " ")
		}
		
		regions = append(regions, region)
	}
	
	return regions
}

// detectMemoryAnomalies looks for suspicious memory patterns
func (s *SignumScanner) detectMemoryAnomalies(proc *ProcessInfo) {
	for i := range proc.MemRegions {
		region := &proc.MemRegions[i]
		
		// Look for executable regions with suspicious characteristics
		if strings.Contains(region.Permissions, "x") {
			// Check for code injection patterns
			s.checkCodeInjection(proc, region)
		}
		
		// Look for RWX regions (potential shellcode)
		if region.Permissions == "rwxp" {
			s.flagSuspiciousRegion(proc, region, "RWX_REGION")
		}
		
		// Check for unusual library mappings
		if strings.Contains(region.Path, ".so") && !s.isKnownLibrary(region.Path) {
			s.flagSuspiciousRegion(proc, region, "UNKNOWN_LIBRARY")
		}
	}
}

// checkCodeInjection looks for signs of code injection
func (s *SignumScanner) checkCodeInjection(proc *ProcessInfo, region *MemoryRegion) {
	// Pattern matching for common shellcode patterns
	suspiciousPatterns := []string{
		"\\x90{10,}", // NOP sleds
		"\\x31\\xc0", // xor eax, eax
		"\\x48\\x31\\xff", // xor rdi, rdi (x64)
		"\\xeb\\xfe", // jmp $
	}
	
	// Try to read memory content (this requires special permissions)
	content := s.readMemoryRegion(proc.PID, region)
	if content == nil {
		return
	}
	
	region.Content = content
	hash := sha256.Sum256(content)
	region.Hash = fmt.Sprintf("%x", hash)
	
	// Check against patterns
	for _, pattern := range suspiciousPatterns {
		if matched, _ := regexp.Match(pattern, content); matched {
			s.flagSuspiciousRegion(proc, region, "SHELLCODE_PATTERN")
			break
		}
	}
}

// readMemoryRegion attempts to read memory from a process region
func (s *SignumScanner) readMemoryRegion(pid int, region *MemoryRegion) []byte {
	// This is a simplified implementation
	// In practice, this would require ptrace or similar low-level access
	memFile := fmt.Sprintf("/proc/%d/mem", pid)
	
	file, err := os.Open(memFile)
	if err != nil {
		return nil
	}
	defer file.Close()
	
	size := region.End - region.Start
	if size > 1024*1024 { // Limit to 1MB for safety
		size = 1024 * 1024
	}
	
	buffer := make([]byte, size)
	_, err = file.ReadAt(buffer, int64(region.Start))
	if err != nil {
		return nil
	}
	
	return buffer
}

// isKnownLibrary checks if a library path is from a known safe source
func (s *SignumScanner) isKnownLibrary(path string) bool {
	knownPaths := []string{
		"/lib/",
		"/usr/lib/",
		"/usr/local/lib/",
		"/lib64/",
		"/usr/lib64/",
	}
	
	for _, known := range knownPaths {
		if strings.HasPrefix(path, known) {
			return true
		}
	}
	
	return false
}

// flagSuspiciousRegion marks a memory region as suspicious
func (s *SignumScanner) flagSuspiciousRegion(proc *ProcessInfo, region *MemoryRegion, reason string) {
	if s.config.Core.Debug {
		fmt.Printf("[SIGNUM] Suspicious region in PID %d (%s): %s - %s\n", 
			proc.PID, proc.Name, reason, region.Path)
	}
}

// continuousMemoryMonitoring runs continuous memory change detection
func (s *SignumScanner) continuousMemoryMonitoring(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.running {
				s.detectMemoryChanges()
			}
		}
	}
}

// detectMemoryChanges compares current state to baseline
func (s *SignumScanner) detectMemoryChanges() {
	for path, baseline := range s.memBaseline {
		current, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		
		currentHash := sha256.Sum256(current)
		currentHashStr := fmt.Sprintf("%x", currentHash)
		
		if s.signalHashes[path] != currentHashStr {
			s.handleMemoryChange(path, baseline, current)
			s.signalHashes[path] = currentHashStr
			s.memBaseline[path] = current
		}
	}
}

// handleMemoryChange processes detected memory changes
func (s *SignumScanner) handleMemoryChange(path string, old, new []byte) {
	if s.config.Core.Debug {
		fmt.Printf("[SIGNUM] Memory change detected in %s\n", path)
	}
	
	// Analyze the type of change
	changeType := s.analyzeMemoryChange(old, new)
	
	// Create alert if necessary
	if s.isCriticalChange(path, changeType) {
		// This would integrate with the alert system
		fmt.Printf("[SIGNUM] CRITICAL: %s change in %s\n", changeType, path)
	}
}

// analyzeMemoryChange determines the type of memory change
func (s *SignumScanner) analyzeMemoryChange(old, new []byte) string {
	if len(new) > len(old) {
		return "MEMORY_EXPANSION"
	}
	if len(new) < len(old) {
		return "MEMORY_REDUCTION"
	}
	return "MEMORY_MODIFICATION"
}

// isCriticalChange determines if a memory change is critical
func (s *SignumScanner) isCriticalChange(path, changeType string) bool {
	criticalPaths := []string{
		"/proc/kallsyms",
		"/proc/modules",
		"/sys/devices/system/cpu/vulnerabilities/",
	}
	
	for _, critical := range criticalPaths {
		if strings.Contains(path, critical) {
			return true
		}
	}
	
	return changeType == "MEMORY_EXPANSION"
}

// signalIntelligenceMonitoring performs RF signal analysis
func (s *SignumScanner) signalIntelligenceMonitoring(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.running {
				s.analyzeRFSignals()
			}
		}
	}
}

// analyzeRFSignals performs signal intelligence analysis
func (s *SignumScanner) analyzeRFSignals() {
	// This would integrate with SDR hardware if available
	// For now, we'll monitor software-detectable signals
	
	// Check wireless interface activity
	s.monitorWirelessActivity()
	
	// Check Bluetooth signal patterns
	s.monitorBluetoothSignals()
	
	// Monitor cellular signal changes
	s.monitorCellularSignals()
}

// monitorWirelessActivity monitors WiFi signal patterns
func (s *SignumScanner) monitorWirelessActivity() {
	// Use iwconfig/iw to get signal information
	cmd := exec.Command("iw", "dev")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	
	// Parse wireless interfaces and their signal data
	s.parseWirelessSignals(string(output))
}

// parseWirelessSignals parses wireless interface signal data
func (s *SignumScanner) parseWirelessSignals(output string) {
	// Implementation would parse iw output and detect signal anomalies
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Interface") {
			// Process interface information
		}
	}
}

// monitorBluetoothSignals monitors Bluetooth signal patterns
func (s *SignumScanner) monitorBluetoothSignals() {
	// Monitor Bluetooth controller status
	cmd := exec.Command("hciconfig")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	
	// Analyze Bluetooth signal patterns
	s.parseBluetoothSignals(string(output))
}

// parseBluetoothSignals parses Bluetooth signal data
func (s *SignumScanner) parseBluetoothSignals(output string) {
	// Look for unusual Bluetooth activity patterns
	if strings.Contains(output, "RUNNING") {
		// Bluetooth is active - monitor for anomalies
	}
}

// monitorCellularSignals monitors cellular signal changes
func (s *SignumScanner) monitorCellularSignals() {
	// Monitor cellular modem if present
	if _, err := os.Stat("/dev/ttyUSB0"); err == nil {
		// Cellular modem detected - monitor AT command responses
		s.analyzeCellularModem("/dev/ttyUSB0")
	}
}

// analyzeCellularModem analyzes cellular modem responses
func (s *SignumScanner) analyzeCellularModem(device string) {
	// This would send AT commands and analyze responses
	// to detect cell tower changes and potential IMSI catchers
}

// processInjectionDetection monitors for process injection attacks
func (s *SignumScanner) processInjectionDetection(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.running {
				s.detectProcessInjection()
			}
		}
	}
}

// detectProcessInjection looks for signs of process injection
func (s *SignumScanner) detectProcessInjection() {
	currentProcesses, err := s.getRunningProcesses()
	if err != nil {
		return
	}
	
	for _, pid := range currentProcesses {
		if _, exists := s.processMap[pid]; !exists {
			// New process detected - analyze it
			if err := s.analyzeProcessMemory(pid); err == nil {
				s.checkNewProcessSuspicion(pid)
			}
		}
	}
	
	// Check for process modifications
	s.checkProcessModifications()
}

// checkNewProcessSuspicion analyzes new processes for suspicious behavior
func (s *SignumScanner) checkNewProcessSuspicion(pid int) {
	proc, exists := s.processMap[pid]
	if !exists {
		return
	}
	
	// Check for suspicious characteristics
	suspicionScore := 0
	
	// Check for unusual parent process
	if s.hasUnusualParent(pid) {
		suspicionScore += 2
	}
	
	// Check for unusual memory layout
	if s.hasUnusualMemoryLayout(proc) {
		suspicionScore += 3
	}
	
	// Check for packed/obfuscated binary
	if s.isPackedBinary(proc) {
		suspicionScore += 2
	}
	
	if suspicionScore >= 4 {
		s.flagSuspiciousProcess(proc, "HIGH_SUSPICION")
	}
}

// hasUnusualParent checks if process has an unusual parent
func (s *SignumScanner) hasUnusualParent(pid int) bool {
	// Check PPID and analyze parent process
	statContent, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	
	fields := strings.Fields(string(statContent))
	if len(fields) < 4 {
		return false
	}
	
	// Field 3 is PPID
	ppid, err := strconv.Atoi(fields[3])
	if err != nil {
		return false
	}
	
	// Check if parent is suspicious
	return s.isSuspiciousParent(ppid)
}

// isSuspiciousParent determines if a parent process is suspicious
func (s *SignumScanner) isSuspiciousParent(ppid int) bool {
	// Common injection targets
	suspiciousParents := []string{
		"svchost.exe", "explorer.exe", "winlogon.exe",
		"csrss.exe", "wininit.exe", "services.exe",
	}
	
	parentProc, exists := s.processMap[ppid]
	if !exists {
		return false
	}
	
	for _, suspicious := range suspiciousParents {
		if strings.Contains(strings.ToLower(parentProc.Name), suspicious) {
			return true
		}
	}
	
	return false
}

// hasUnusualMemoryLayout checks for unusual memory patterns
func (s *SignumScanner) hasUnusualMemoryLayout(proc *ProcessInfo) bool {
	rwxCount := 0
	largeGaps := 0
	
	for i, region := range proc.MemRegions {
		// Count RWX regions
		if region.Permissions == "rwxp" {
			rwxCount++
		}
		
		// Check for large gaps in memory layout
		if i > 0 {
			gap := region.Start - proc.MemRegions[i-1].End
			if gap > 0x10000000 { // 256MB gap
				largeGaps++
			}
		}
	}
	
	return rwxCount > 2 || largeGaps > 3
}

// isPackedBinary checks if binary appears to be packed
func (s *SignumScanner) isPackedBinary(proc *ProcessInfo) bool {
	// Look for signs of packing/obfuscation
	for _, region := range proc.MemRegions {
		if region.Content == nil {
			continue
		}
		
		// High entropy might indicate packing
		if s.calculateEntropy(region.Content) > 7.0 {
			return true
		}
		
		// Look for common packer signatures
		packerSigs := [][]byte{
			[]byte("UPX!"), // UPX packer
			[]byte("PECompact"), // PECompact
			[]byte("ASPack"), // ASPack
		}
		
		for _, sig := range packerSigs {
			if s.containsBytes(region.Content, sig) {
				return true
			}
		}
	}
	
	return false
}

// calculateEntropy calculates the entropy of a byte array
func (s *SignumScanner) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	
	entropy := 0.0
	length := float64(len(data))
	
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * (logBase2(p))
		}
	}
	
	return entropy
}

// logBase2 calculates log base 2
func logBase2(x float64) float64 {
	return 1.4426950408889634 * 2.302585092994046 * x // log2(x) approximation
}

// containsBytes checks if data contains a byte sequence
func (s *SignumScanner) containsBytes(data, pattern []byte) bool {
	for i := 0; i <= len(data)-len(pattern); i++ {
		match := true
		for j := 0; j < len(pattern); j++ {
			if data[i+j] != pattern[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// checkProcessModifications checks for modifications to existing processes
func (s *SignumScanner) checkProcessModifications() {
	for pid, proc := range s.processMap {
		// Re-analyze process memory
		if err := s.analyzeProcessMemory(pid); err != nil {
			// Process may have exited
			delete(s.processMap, pid)
			continue
		}
		
		// Compare with previous state
		s.compareProcessState(proc)
	}
}

// compareProcessState compares current process state with baseline
func (s *SignumScanner) compareProcessState(proc *ProcessInfo) {
	// This would compare memory regions, loaded modules, etc.
	// with the previous state to detect runtime modifications
}

// flagSuspiciousProcess flags a process as suspicious
func (s *SignumScanner) flagSuspiciousProcess(proc *ProcessInfo, reason string) {
	if s.config.Core.Debug {
		fmt.Printf("[SIGNUM] Suspicious process detected: PID %d (%s) - %s\n", 
			proc.PID, proc.Name, reason)
	}
}

// GetSignumResults returns current signum scan results
func (s *SignumScanner) GetSignumResults() map[string]interface{} {
	results := make(map[string]interface{})
	
	results["processes_monitored"] = len(s.processMap)
	results["memory_regions_tracked"] = len(s.memBaseline)
	results["signal_hashes"] = len(s.signalHashes)
	results["running"] = s.running
	
	// Count suspicious processes
	suspiciousCount := 0
	for _, proc := range s.processMap {
		if len(proc.Signals) > 0 {
			suspiciousCount++
		}
	}
	results["suspicious_processes"] = suspiciousCount
	
	return results
}

// IsAvailable checks if signum scanning capabilities are available
func (s *SignumScanner) IsAvailable() bool {
	// Check if we have necessary permissions and tools
	if os.Geteuid() != 0 {
		return false // Need root for memory access
	}
	
	// Check if /proc is available
	if _, err := os.Stat("/proc"); err != nil {
		return false
	}
	
	return true
}

// GetType returns the scanner type
func (s *SignumScanner) GetType() string {
	return "signum"
}
