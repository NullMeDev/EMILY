//go:build linux
// +build linux

package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/null/emily/internal/config"
)

// IntrusionScanner implements advanced intrusion detection for the device
// Monitors network connections, file system changes, and system calls
type IntrusionScanner struct {
	config           *config.Config
	running          bool
	mutex            sync.RWMutex
	networkBaseline  map[string]*NetworkConnection
	fileBaseline     map[string]*FileInfo
	processBaseline  map[int]*ProcessState
	loginAttempts    []LoginAttempt
	networkActivity  []NetworkEvent
	suspiciousFiles  []SuspiciousFile
	alertThresholds  *AlertThresholds
}

// NetworkConnection represents a network connection
type NetworkConnection struct {
	LocalAddr    string
	RemoteAddr   string
	State        string
	Protocol     string
	PID          int
	ProcessName  string
	Timestamp    time.Time
	BytesSent    uint64
	BytesRecv    uint64
	Suspicious   bool
}

// FileInfo represents file system information
type FileInfo struct {
	Path         string
	Size         int64
	Mode         os.FileMode
	ModTime      time.Time
	Checksum     string
	Owner        string
	Group        string
	Permissions  string
	Suspicious   bool
}

// ProcessState represents process state information
type ProcessState struct {
	PID          int
	PPID         int
	Name         string
	Cmdline      string
	StartTime    time.Time
	CPUTime      time.Duration
	MemoryUsage  uint64
	OpenFiles    []string
	NetworkConns []string
	Suspicious   bool
}

// LoginAttempt represents a login attempt
type LoginAttempt struct {
	Username    string
	Source      string
	Timestamp   time.Time
	Success     bool
	Method      string
	UserAgent   string
	Suspicious  bool
}

// NetworkEvent represents a network event
type NetworkEvent struct {
	Type        string
	Source      string
	Destination string
	Protocol    string
	Port        int
	Timestamp   time.Time
	Data        []byte
	Suspicious  bool
}

// SuspiciousFile represents a suspicious file
type SuspiciousFile struct {
	Path        string
	Reason      string
	Timestamp   time.Time
	Size        int64
	Hash        string
	Quarantined bool
}

// AlertThresholds defines thresholds for various alerts
type AlertThresholds struct {
	MaxLoginAttempts     int
	MaxNetworkConns      int
	MaxFileChanges       int
	MaxProcesses         int
	SuspiciousFileSize   int64
	NetworkTimeoutSec    int
	LoginTimeoutSec      int
}

// NewIntrusionScanner creates a new intrusion detection scanner
func NewIntrusionScanner(cfg *config.Config) *IntrusionScanner {
	return &IntrusionScanner{
		config:          cfg,
		networkBaseline: make(map[string]*NetworkConnection),
		fileBaseline:    make(map[string]*FileInfo),
		processBaseline: make(map[int]*ProcessState),
		loginAttempts:   make([]LoginAttempt, 0),
		networkActivity: make([]NetworkEvent, 0),
		suspiciousFiles: make([]SuspiciousFile, 0),
		alertThresholds: &AlertThresholds{
			MaxLoginAttempts:   10,
			MaxNetworkConns:    100,
			MaxFileChanges:     50,
			MaxProcesses:       500,
			SuspiciousFileSize: 100 * 1024 * 1024, // 100MB
			NetworkTimeoutSec:  300,                // 5 minutes
			LoginTimeoutSec:    3600,               // 1 hour
		},
	}
}

// Start initializes the intrusion detection scanner
func (i *IntrusionScanner) Start(ctx context.Context) error {
	i.running = true
	
	// Initialize baselines
	if err := i.initializeBaselines(); err != nil {
		return fmt.Errorf("failed to initialize baselines: %w", err)
	}
	
	// Start monitoring goroutines
	go i.monitorNetworkConnections(ctx)
	go i.monitorFileSystem(ctx)
	go i.monitorProcesses(ctx)
	go i.monitorLoginAttempts(ctx)
	go i.monitorNetworkTraffic(ctx)
	go i.analyzeThreats(ctx)
	
	return nil
}

// Stop stops the intrusion detection scanner
func (i *IntrusionScanner) Stop() error {
	i.running = false
	return nil
}

// initializeBaselines creates initial baselines for comparison
func (i *IntrusionScanner) initializeBaselines() error {
	// Initialize network baseline
	if err := i.scanNetworkConnections(); err != nil {
		return fmt.Errorf("failed to scan network connections: %w", err)
	}
	
	// Initialize file system baseline
	if err := i.scanFileSystem(); err != nil {
		return fmt.Errorf("failed to scan file system: %w", err)
	}
	
	// Initialize process baseline
	if err := i.scanProcesses(); err != nil {
		return fmt.Errorf("failed to scan processes: %w", err)
	}
	
	return nil
}

// scanNetworkConnections scans current network connections
func (i *IntrusionScanner) scanNetworkConnections() error {
	// Read /proc/net/tcp and /proc/net/udp
	protocols := []string{"tcp", "udp", "tcp6", "udp6"}
	
	for _, protocol := range protocols {
		if err := i.parseNetstatFile(protocol); err != nil {
			continue // Continue with other protocols
		}
	}
	
	return nil
}

// parseNetstatFile parses /proc/net/* files
func (i *IntrusionScanner) parseNetstatFile(protocol string) error {
	filename := fmt.Sprintf("/proc/net/%s", protocol)
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // Skip header
		}
		
		line := scanner.Text()
		conn := i.parseNetstatLine(line, protocol)
		if conn != nil {
			key := fmt.Sprintf("%s:%s->%s", protocol, conn.LocalAddr, conn.RemoteAddr)
			i.networkBaseline[key] = conn
		}
	}
	
	return scanner.Err()
}

// parseNetstatLine parses a single line from /proc/net/* files
func (i *IntrusionScanner) parseNetstatLine(line, protocol string) *NetworkConnection {
	fields := strings.Fields(line)
	if len(fields) < 12 {
		return nil
	}
	
	// Parse local address
	localAddr := i.parseNetAddr(fields[1])
	// Parse remote address
	remoteAddr := i.parseNetAddr(fields[2])
	// Parse state
	state := i.parseNetState(fields[3])
	// Parse PID (if available in fields[10])
	var pid int
	if len(fields) > 10 {
		pid, _ = strconv.Atoi(fields[10])
	}
	
	return &NetworkConnection{
		LocalAddr:   localAddr,
		RemoteAddr:  remoteAddr,
		State:       state,
		Protocol:    protocol,
		PID:         pid,
		Timestamp:   time.Now(),
		Suspicious:  i.isNetworkConnectionSuspicious(localAddr, remoteAddr, protocol),
	}
}

// parseNetAddr parses network address from hex format
func (i *IntrusionScanner) parseNetAddr(hexAddr string) string {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return hexAddr
	}
	
	// Parse IP (in hex, little endian)
	ipHex := parts[0]
	portHex := parts[1]
	
	// Convert hex IP to decimal
	if len(ipHex) == 8 { // IPv4
		ip := make([]byte, 4)
		for j := 0; j < 4; j++ {
			val, err := strconv.ParseUint(ipHex[j*2:(j+1)*2], 16, 8)
			if err != nil {
				return hexAddr
			}
			ip[3-j] = byte(val) // Little endian
		}
		
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			return hexAddr
		}
		
		return fmt.Sprintf("%d.%d.%d.%d:%d", ip[0], ip[1], ip[2], ip[3], port)
	}
	
	return hexAddr
}

// parseNetState parses network connection state
func (i *IntrusionScanner) parseNetState(hexState string) string {
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}
	
	if state, exists := states[strings.ToUpper(hexState)]; exists {
		return state
	}
	return "UNKNOWN"
}

// isNetworkConnectionSuspicious determines if a network connection is suspicious
func (i *IntrusionScanner) isNetworkConnectionSuspicious(local, remote, protocol string) bool {
	// Check for suspicious ports
	suspiciousPorts := []int{22, 23, 135, 139, 445, 1433, 3389, 5432}
	
	// Extract port from remote address
	parts := strings.Split(remote, ":")
	if len(parts) == 2 {
		if port, err := strconv.Atoi(parts[1]); err == nil {
			for _, suspPort := range suspiciousPorts {
				if port == suspPort {
					return true
				}
			}
		}
	}
	
	// Check for unusual remote addresses
	if i.isUnusualRemoteAddress(remote) {
		return true
	}
	
	return false
}

// isUnusualRemoteAddress checks if remote address is unusual
func (i *IntrusionScanner) isUnusualRemoteAddress(remote string) bool {
	// Check for private networks connecting outbound (potential tunneling)
	privateRanges := []string{
		"10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
		"172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
		"172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
	}
	
	for _, private := range privateRanges {
		if strings.HasPrefix(remote, private) {
			return true
		}
	}
	
	// Check for known malicious IP ranges (simplified)
	if strings.HasPrefix(remote, "0.0.0.0") || strings.HasPrefix(remote, "127.") {
		return false // Localhost is OK
	}
	
	return false
}

// scanFileSystem scans critical file system locations
func (i *IntrusionScanner) scanFileSystem() error {
	criticalPaths := []string{
		"/etc/passwd",
		"/etc/shadow",
		"/etc/sudoers",
		"/etc/hosts",
		"/etc/ssh/sshd_config",
		"/root/.ssh/authorized_keys",
		"/home/*/.ssh/authorized_keys",
		"/bin",
		"/usr/bin",
		"/sbin",
		"/usr/sbin",
		"/etc/systemd/system",
		"/var/log",
	}
	
	for _, path := range criticalPaths {
		if strings.Contains(path, "*") {
			// Handle glob patterns
			i.scanGlobPath(path)
		} else {
			i.scanSinglePath(path)
		}
	}
	
	return nil
}

// scanGlobPath scans paths with glob patterns
func (i *IntrusionScanner) scanGlobPath(pattern string) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("ls -la %s 2>/dev/null", pattern))
	output, err := cmd.Output()
	if err != nil {
		return
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		
		fields := strings.Fields(line)
		if len(fields) >= 9 {
			path := strings.Join(fields[8:], " ")
			i.scanSinglePath(path)
		}
	}
}

// scanSinglePath scans a single file or directory
func (i *IntrusionScanner) scanSinglePath(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	
	fileInfo := &FileInfo{
		Path:        path,
		Size:        info.Size(),
		Mode:        info.Mode(),
		ModTime:     info.ModTime(),
		Permissions: info.Mode().String(),
		Suspicious:  i.isFileSuspicious(path, info),
	}
	
	// Calculate checksum for critical files
	if info.Size() < 10*1024*1024 { // Only for files < 10MB
		fileInfo.Checksum = i.calculateFileChecksum(path)
	}
	
	i.fileBaseline[path] = fileInfo
}

// isFileSuspicious determines if a file is suspicious
func (i *IntrusionScanner) isFileSuspicious(path string, info os.FileInfo) bool {
	// Check for unusual permissions
	if info.Mode().Perm()&0002 != 0 { // World writable
		return true
	}
	
	// Check for setuid/setgid files in unusual locations
	if info.Mode()&os.ModeSetuid != 0 || info.Mode()&os.ModeSetgid != 0 {
		if !i.isKnownSetuidPath(path) {
			return true
		}
	}
	
	// Check for hidden executables
	filename := path[strings.LastIndex(path, "/")+1:]
	if strings.HasPrefix(filename, ".") && info.Mode().Perm()&0111 != 0 {
		return true
	}
	
	// Check for unusually large files
	if info.Size() > i.alertThresholds.SuspiciousFileSize {
		return true
	}
	
	return false
}

// isKnownSetuidPath checks if path is a known location for setuid files
func (i *IntrusionScanner) isKnownSetuidPath(path string) bool {
	knownPaths := []string{
		"/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/",
		"/usr/local/bin/", "/usr/local/sbin/",
	}
	
	for _, known := range knownPaths {
		if strings.HasPrefix(path, known) {
			return true
		}
	}
	
	return false
}

// calculateFileChecksum calculates file checksum
func (i *IntrusionScanner) calculateFileChecksum(path string) string {
	cmd := exec.Command("sha256sum", path)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	
	fields := strings.Fields(string(output))
	if len(fields) > 0 {
		return fields[0]
	}
	
	return ""
}

// scanProcesses scans running processes
func (i *IntrusionScanner) scanProcesses() error {
	files, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	
	for _, file := range files {
		if pid, err := strconv.Atoi(file.Name()); err == nil {
			if procState := i.getProcessState(pid); procState != nil {
				i.processBaseline[pid] = procState
			}
		}
	}
	
	return nil
}

// getProcessState gets detailed process state
func (i *IntrusionScanner) getProcessState(pid int) *ProcessState {
	// Read process information
	statContent, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil
	}
	
	cmdlineContent, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	commContent, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	
	// Parse process information
	statFields := strings.Fields(string(statContent))
	if len(statFields) < 24 {
		return nil
	}
	
	ppid, _ := strconv.Atoi(statFields[3])
	
	name := strings.TrimSpace(string(commContent))
	cmdline := strings.ReplaceAll(string(cmdlineContent), "\x00", " ")
	
	procState := &ProcessState{
		PID:         pid,
		PPID:        ppid,
		Name:        name,
		Cmdline:     cmdline,
		StartTime:   time.Now(), // Simplified
		OpenFiles:   i.getProcessOpenFiles(pid),
		Suspicious:  i.isProcessSuspicious(pid, name, cmdline),
	}
	
	return procState
}

// getProcessOpenFiles gets list of open files for a process
func (i *IntrusionScanner) getProcessOpenFiles(pid int) []string {
	var files []string
	
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	fdFiles, err := os.ReadDir(fdDir)
	if err != nil {
		return files
	}
	
	for _, fdFile := range fdFiles {
		if fdFile.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, fdFile.Name()))
			if err == nil {
				files = append(files, target)
			}
		}
	}
	
	return files
}

// isProcessSuspicious determines if a process is suspicious
func (i *IntrusionScanner) isProcessSuspicious(pid int, name, cmdline string) bool {
	// Check for suspicious process names
	suspiciousNames := []string{
		"nc", "netcat", "ncat", "socat", "telnet",
		"python", "perl", "ruby", "bash", "sh",
		"powershell", "cmd", "wget", "curl",
	}
	
	for _, suspicious := range suspiciousNames {
		if strings.Contains(strings.ToLower(name), suspicious) {
			return true
		}
	}
	
	// Check for suspicious command line patterns
	suspiciousPatterns := []string{
		"/dev/tcp/", "/dev/udp/", "bash -i", "sh -i",
		"nc -l", "netcat -l", "python -c", "perl -e",
		"base64 -d", "echo ", "wget ", "curl ",
	}
	
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(cmdline), pattern) {
			return true
		}
	}
	
	return false
}

// monitorNetworkConnections continuously monitors network connections
func (i *IntrusionScanner) monitorNetworkConnections(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if i.running {
				i.checkNetworkChanges()
			}
		}
	}
}

// checkNetworkChanges checks for new or changed network connections
func (i *IntrusionScanner) checkNetworkChanges() {
	currentConnections := make(map[string]*NetworkConnection)
	
	// Scan current connections
	protocols := []string{"tcp", "udp", "tcp6", "udp6"}
	for _, protocol := range protocols {
		i.parseNetstatFileIntoMap(protocol, currentConnections)
	}
	
	// Compare with baseline
	for key, conn := range currentConnections {
		if _, exists := i.networkBaseline[key]; !exists {
			// New connection detected
			i.handleNewNetworkConnection(conn)
		}
	}
	
	// Update baseline
	i.networkBaseline = currentConnections
}

// parseNetstatFileIntoMap parses netstat file into provided map
func (i *IntrusionScanner) parseNetstatFileIntoMap(protocol string, connections map[string]*NetworkConnection) {
	filename := fmt.Sprintf("/proc/net/%s", protocol)
	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			continue // Skip header
		}
		
		line := scanner.Text()
		conn := i.parseNetstatLine(line, protocol)
		if conn != nil {
			key := fmt.Sprintf("%s:%s->%s", protocol, conn.LocalAddr, conn.RemoteAddr)
			connections[key] = conn
		}
	}
}

// handleNewNetworkConnection handles detection of new network connection
func (i *IntrusionScanner) handleNewNetworkConnection(conn *NetworkConnection) {
	if i.config.Core.Debug {
		fmt.Printf("[INTRUSION] New network connection: %s %s->%s (PID: %d)\n",
			conn.Protocol, conn.LocalAddr, conn.RemoteAddr, conn.PID)
	}
	
	if conn.Suspicious {
		i.createNetworkAlert(conn)
	}
}

// createNetworkAlert creates an alert for suspicious network activity
func (i *IntrusionScanner) createNetworkAlert(conn *NetworkConnection) {
	event := NetworkEvent{
		Type:        "SUSPICIOUS_CONNECTION",
		Source:      conn.LocalAddr,
		Destination: conn.RemoteAddr,
		Protocol:    conn.Protocol,
		Timestamp:   time.Now(),
		Suspicious:  true,
	}
	
	i.networkActivity = append(i.networkActivity, event)
	
	if i.config.Core.Debug {
		fmt.Printf("[INTRUSION] ALERT: Suspicious network connection: %s->%s\n",
			conn.LocalAddr, conn.RemoteAddr)
	}
}

// monitorFileSystem continuously monitors file system changes
func (i *IntrusionScanner) monitorFileSystem(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if i.running {
				i.checkFileSystemChanges()
			}
		}
	}
}

// checkFileSystemChanges checks for file system changes
func (i *IntrusionScanner) checkFileSystemChanges() {
	currentFiles := make(map[string]*FileInfo)
	
	// Scan current file system state
	i.scanFileSystemIntoMap(currentFiles)
	
	// Compare with baseline
	for path, fileInfo := range currentFiles {
		if baseline, exists := i.fileBaseline[path]; exists {
			if i.hasFileChanged(baseline, fileInfo) {
				i.handleFileChange(path, baseline, fileInfo)
			}
		} else {
			// New file detected
			i.handleNewFile(fileInfo)
		}
	}
	
	// Check for deleted files
	for path := range i.fileBaseline {
		if _, exists := currentFiles[path]; !exists {
			i.handleDeletedFile(path)
		}
	}
	
	// Update baseline
	i.fileBaseline = currentFiles
}

// scanFileSystemIntoMap scans file system into provided map
func (i *IntrusionScanner) scanFileSystemIntoMap(files map[string]*FileInfo) {
	criticalPaths := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
		"/etc/ssh/sshd_config", "/bin", "/usr/bin",
	}
	
	for _, path := range criticalPaths {
		i.scanSinglePathIntoMap(path, files)
	}
}

// scanSinglePathIntoMap scans single path into map
func (i *IntrusionScanner) scanSinglePathIntoMap(path string, files map[string]*FileInfo) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	
	fileInfo := &FileInfo{
		Path:        path,
		Size:        info.Size(),
		Mode:        info.Mode(),
		ModTime:     info.ModTime(),
		Permissions: info.Mode().String(),
		Suspicious:  i.isFileSuspicious(path, info),
	}
	
	if info.Size() < 10*1024*1024 {
		fileInfo.Checksum = i.calculateFileChecksum(path)
	}
	
	files[path] = fileInfo
}

// hasFileChanged checks if file has changed
func (i *IntrusionScanner) hasFileChanged(baseline, current *FileInfo) bool {
	return baseline.Size != current.Size ||
		baseline.ModTime != current.ModTime ||
		baseline.Checksum != current.Checksum ||
		baseline.Permissions != current.Permissions
}

// handleFileChange handles file change detection
func (i *IntrusionScanner) handleFileChange(path string, baseline, current *FileInfo) {
	if i.config.Core.Debug {
		fmt.Printf("[INTRUSION] File changed: %s\n", path)
	}
	
	if current.Suspicious || i.isCriticalFile(path) {
		i.createFileAlert(path, "FILE_MODIFIED", current)
	}
}

// handleNewFile handles new file detection
func (i *IntrusionScanner) handleNewFile(fileInfo *FileInfo) {
	if i.config.Core.Debug {
		fmt.Printf("[INTRUSION] New file: %s\n", fileInfo.Path)
	}
	
	if fileInfo.Suspicious {
		i.createFileAlert(fileInfo.Path, "SUSPICIOUS_FILE_CREATED", fileInfo)
	}
}

// handleDeletedFile handles file deletion detection
func (i *IntrusionScanner) handleDeletedFile(path string) {
	if i.config.Core.Debug {
		fmt.Printf("[INTRUSION] File deleted: %s\n", path)
	}
	
	if i.isCriticalFile(path) {
		fileInfo := &FileInfo{Path: path}
		i.createFileAlert(path, "CRITICAL_FILE_DELETED", fileInfo)
	}
}

// isCriticalFile checks if file is critical
func (i *IntrusionScanner) isCriticalFile(path string) bool {
	criticalFiles := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/etc/ssh/sshd_config", "/root/.ssh/authorized_keys",
	}
	
	for _, critical := range criticalFiles {
		if strings.Contains(path, critical) {
			return true
		}
	}
	
	return false
}

// createFileAlert creates an alert for file system activity
func (i *IntrusionScanner) createFileAlert(path, alertType string, fileInfo *FileInfo) {
	suspiciousFile := SuspiciousFile{
		Path:      path,
		Reason:    alertType,
		Timestamp: time.Now(),
		Size:      fileInfo.Size,
		Hash:      fileInfo.Checksum,
	}
	
	i.suspiciousFiles = append(i.suspiciousFiles, suspiciousFile)
	
	if i.config.Core.Debug {
		fmt.Printf("[INTRUSION] ALERT: %s - %s\n", alertType, path)
	}
}

// monitorProcesses continuously monitors processes
func (i *IntrusionScanner) monitorProcesses(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if i.running {
				i.checkProcessChanges()
			}
		}
	}
}

// checkProcessChanges checks for process changes
func (i *IntrusionScanner) checkProcessChanges() {
	currentProcesses := make(map[int]*ProcessState)
	
	// Scan current processes
	files, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	
	for _, file := range files {
		if pid, err := strconv.Atoi(file.Name()); err == nil {
			if procState := i.getProcessState(pid); procState != nil {
				currentProcesses[pid] = procState
			}
		}
	}
	
	// Check for new processes
	for pid, procState := range currentProcesses {
		if _, exists := i.processBaseline[pid]; !exists {
			i.handleNewProcess(procState)
		}
	}
	
	// Update baseline
	i.processBaseline = currentProcesses
}

// handleNewProcess handles new process detection
func (i *IntrusionScanner) handleNewProcess(procState *ProcessState) {
	if i.config.Core.Debug {
		fmt.Printf("[INTRUSION] New process: PID %d (%s) - %s\n",
			procState.PID, procState.Name, procState.Cmdline)
	}
	
	if procState.Suspicious {
		i.createProcessAlert(procState)
	}
}

// createProcessAlert creates an alert for suspicious process
func (i *IntrusionScanner) createProcessAlert(procState *ProcessState) {
	if i.config.Core.Debug {
		fmt.Printf("[INTRUSION] ALERT: Suspicious process: PID %d (%s)\n",
			procState.PID, procState.Name)
	}
}

// monitorLoginAttempts monitors login attempts
func (i *IntrusionScanner) monitorLoginAttempts(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if i.running {
				i.checkLoginAttempts()
			}
		}
	}
}

// checkLoginAttempts checks system logs for login attempts
func (i *IntrusionScanner) checkLoginAttempts() {
	// Read auth log
	authLogs := []string{"/var/log/auth.log", "/var/log/secure"}
	
	for _, logFile := range authLogs {
		i.parseAuthLog(logFile)
	}
}

// parseAuthLog parses authentication log files
func (i *IntrusionScanner) parseAuthLog(logFile string) {
	file, err := os.Open(logFile)
	if err != nil {
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if loginAttempt := i.parseLoginLine(line); loginAttempt != nil {
			i.processLoginAttempt(*loginAttempt)
		}
	}
}

// parseLoginLine parses a login attempt from log line
func (i *IntrusionScanner) parseLoginLine(line string) *LoginAttempt {
	// Simple parsing for SSH login attempts
	if strings.Contains(line, "ssh") && strings.Contains(line, "Failed") {
		// Extract username and source IP
		re := regexp.MustCompile(`Failed password for (\w+) from ([\d.]+)`)
		matches := re.FindStringSubmatch(line)
		if len(matches) >= 3 {
			return &LoginAttempt{
				Username:   matches[1],
				Source:     matches[2],
				Timestamp:  time.Now(),
				Success:    false,
				Method:     "ssh",
				Suspicious: true,
			}
		}
	}
	
	return nil
}

// processLoginAttempt processes a login attempt
func (i *IntrusionScanner) processLoginAttempt(attempt LoginAttempt) {
	i.loginAttempts = append(i.loginAttempts, attempt)
	
	if attempt.Suspicious {
		i.analyzeLoginPattern(attempt)
	}
}

// analyzeLoginPattern analyzes login patterns for threats
func (i *IntrusionScanner) analyzeLoginPattern(attempt LoginAttempt) {
	// Count failed attempts from same source
	failedCount := 0
	for _, prevAttempt := range i.loginAttempts {
		if prevAttempt.Source == attempt.Source && !prevAttempt.Success {
			failedCount++
		}
	}
	
	if failedCount > i.alertThresholds.MaxLoginAttempts {
		i.createLoginAlert(attempt, "BRUTE_FORCE_DETECTED")
	}
}

// createLoginAlert creates an alert for suspicious login activity
func (i *IntrusionScanner) createLoginAlert(attempt LoginAttempt, alertType string) {
	if i.config.Core.Debug {
		fmt.Printf("[INTRUSION] ALERT: %s from %s (user: %s)\n",
			alertType, attempt.Source, attempt.Username)
	}
}

// monitorNetworkTraffic monitors network traffic patterns
func (i *IntrusionScanner) monitorNetworkTraffic(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if i.running {
				i.analyzeNetworkTraffic()
			}
		}
	}
}

// analyzeNetworkTraffic analyzes network traffic for anomalies
func (i *IntrusionScanner) analyzeNetworkTraffic() {
	// Monitor network interface statistics
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			i.analyzeInterfaceTraffic(iface)
		}
	}
}

// analyzeInterfaceTraffic analyzes traffic on a specific interface
func (i *IntrusionScanner) analyzeInterfaceTraffic(iface net.Interface) {
	// Read interface statistics from /proc/net/dev
	statFile := "/proc/net/dev"
	content, err := os.ReadFile(statFile)
	if err != nil {
		return
	}
	
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.Contains(line, iface.Name+":") {
			i.parseInterfaceStats(iface.Name, line)
			break
		}
	}
}

// parseInterfaceStats parses interface statistics
func (i *IntrusionScanner) parseInterfaceStats(ifaceName, statLine string) {
	fields := strings.Fields(statLine)
	if len(fields) < 16 {
		return
	}
	
	// Extract RX and TX bytes (fields 1 and 9)
	rxBytes, _ := strconv.ParseUint(fields[1], 10, 64)
	txBytes, _ := strconv.ParseUint(fields[9], 10, 64)
	
	// Analyze for unusual traffic patterns
	if i.isUnusualTraffic(ifaceName, rxBytes, txBytes) {
		i.createTrafficAlert(ifaceName, rxBytes, txBytes)
	}
}

// isUnusualTraffic determines if traffic pattern is unusual
func (i *IntrusionScanner) isUnusualTraffic(ifaceName string, rxBytes, txBytes uint64) bool {
	// Simple heuristic: check for very high traffic
	threshold := uint64(100 * 1024 * 1024) // 100MB
	return rxBytes > threshold || txBytes > threshold
}

// createTrafficAlert creates an alert for unusual traffic
func (i *IntrusionScanner) createTrafficAlert(ifaceName string, rxBytes, txBytes uint64) {
	event := NetworkEvent{
		Type:      "UNUSUAL_TRAFFIC",
		Source:    ifaceName,
		Timestamp: time.Now(),
		Suspicious: true,
	}
	
	i.networkActivity = append(i.networkActivity, event)
	
	if i.config.Core.Debug {
		fmt.Printf("[INTRUSION] ALERT: Unusual traffic on %s (RX: %d, TX: %d)\n",
			ifaceName, rxBytes, txBytes)
	}
}

// analyzeThreats performs advanced threat analysis
func (i *IntrusionScanner) analyzeThreats(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if i.running {
				i.performThreatAnalysis()
			}
		}
	}
}

// performThreatAnalysis performs comprehensive threat analysis
func (i *IntrusionScanner) performThreatAnalysis() {
	// Analyze correlation between different events
	i.analyzeEventCorrelation()
	
	// Check for known attack patterns
	i.checkAttackPatterns()
	
	// Perform behavioral analysis
	i.performBehavioralAnalysis()
}

// analyzeEventCorrelation analyzes correlation between different security events
func (i *IntrusionScanner) analyzeEventCorrelation() {
	// Look for patterns like new process + network connection + file change
	recentTime := time.Now().Add(-5 * time.Minute)
	
	recentNetworkEvents := 0
	recentFileChanges := 0
	recentProcesses := 0
	
	for _, event := range i.networkActivity {
		if event.Timestamp.After(recentTime) && event.Suspicious {
			recentNetworkEvents++
		}
	}
	
	for _, file := range i.suspiciousFiles {
		if file.Timestamp.After(recentTime) {
			recentFileChanges++
		}
	}
	
	for _, proc := range i.processBaseline {
		if proc.Suspicious {
			recentProcesses++
		}
	}
	
	// If multiple suspicious events, create high-priority alert
	if recentNetworkEvents > 0 && recentFileChanges > 0 && recentProcesses > 0 {
		i.createCorrelatedThreatAlert()
	}
}

// createCorrelatedThreatAlert creates an alert for correlated threats
func (i *IntrusionScanner) createCorrelatedThreatAlert() {
	if i.config.Core.Debug {
		fmt.Printf("[INTRUSION] CRITICAL ALERT: Correlated threat activity detected!\n")
	}
}

// checkAttackPatterns checks for known attack patterns
func (i *IntrusionScanner) checkAttackPatterns() {
	// Check for common attack patterns
	i.checkForWebShell()
	i.checkForReverseShell()
	i.checkForPrivilegeEscalation()
}

// checkForWebShell checks for web shell indicators
func (i *IntrusionScanner) checkForWebShell() {
	webShellIndicators := []string{
		"php", "asp", "jsp", "eval", "exec", "system",
		"passthru", "shell_exec", "base64_decode",
	}
	
	for _, proc := range i.processBaseline {
		if proc.Suspicious {
			for _, indicator := range webShellIndicators {
				if strings.Contains(strings.ToLower(proc.Cmdline), indicator) {
					i.createAttackAlert("WEB_SHELL_DETECTED", proc.Cmdline)
					break
				}
			}
		}
	}
}

// checkForReverseShell checks for reverse shell indicators
func (i *IntrusionScanner) checkForReverseShell() {
	reverseShellPatterns := []string{
		"bash -i", "sh -i", "/dev/tcp/", "nc -e", "netcat -e",
		"python -c", "perl -e", "ruby -rsocket",
	}
	
	for _, proc := range i.processBaseline {
		if proc.Suspicious {
			for _, pattern := range reverseShellPatterns {
				if strings.Contains(strings.ToLower(proc.Cmdline), pattern) {
					i.createAttackAlert("REVERSE_SHELL_DETECTED", proc.Cmdline)
					break
				}
			}
		}
	}
}

// checkForPrivilegeEscalation checks for privilege escalation attempts
func (i *IntrusionScanner) checkForPrivilegeEscalation() {
	escalationIndicators := []string{
		"sudo", "su", "setuid", "setgid", "chmod +s",
		"sudoers", "/etc/passwd", "/etc/shadow",
	}
	
	for _, file := range i.suspiciousFiles {
		for _, indicator := range escalationIndicators {
			if strings.Contains(strings.ToLower(file.Path), indicator) {
				i.createAttackAlert("PRIVILEGE_ESCALATION_ATTEMPT", file.Path)
				break
			}
		}
	}
}

// createAttackAlert creates an alert for detected attack pattern
func (i *IntrusionScanner) createAttackAlert(attackType, details string) {
	if i.config.Core.Debug {
		fmt.Printf("[INTRUSION] ATTACK ALERT: %s - %s\n", attackType, details)
	}
}

// performBehavioralAnalysis performs behavioral analysis
func (i *IntrusionScanner) performBehavioralAnalysis() {
	// Analyze process behavior patterns
	i.analyzeBehavioralPatterns()
	
	// Check for anomalous resource usage
	i.checkResourceAnomalies()
}

// analyzeBehavioralPatterns analyzes behavioral patterns
func (i *IntrusionScanner) analyzeBehavioralPatterns() {
	// Look for processes that spawn many children
	childCountMap := make(map[int]int)
	
	for _, proc := range i.processBaseline {
		childCountMap[proc.PPID]++
	}
	
	for ppid, childCount := range childCountMap {
		if childCount > 10 { // Suspicious if more than 10 children
			if parent, exists := i.processBaseline[ppid]; exists {
				i.createBehavioralAlert("EXCESSIVE_CHILD_PROCESSES", parent.Name)
			}
		}
	}
}

// checkResourceAnomalies checks for resource usage anomalies
func (i *IntrusionScanner) checkResourceAnomalies() {
	// Check for processes with unusual resource consumption
	for _, proc := range i.processBaseline {
		if proc.MemoryUsage > 1024*1024*1024 { // > 1GB memory
			i.createBehavioralAlert("HIGH_MEMORY_USAGE", proc.Name)
		}
	}
}

// createBehavioralAlert creates an alert for behavioral anomaly
func (i *IntrusionScanner) createBehavioralAlert(alertType, details string) {
	if i.config.Core.Debug {
		fmt.Printf("[INTRUSION] BEHAVIORAL ALERT: %s - %s\n", alertType, details)
	}
}

// GetIntrusionResults returns current intrusion detection results
func (i *IntrusionScanner) GetIntrusionResults() map[string]interface{} {
	i.mutex.RLock()
	defer i.mutex.RUnlock()
	
	results := make(map[string]interface{})
	
	results["network_connections"] = len(i.networkBaseline)
	results["files_monitored"] = len(i.fileBaseline)
	results["processes_monitored"] = len(i.processBaseline)
	results["login_attempts"] = len(i.loginAttempts)
	results["network_events"] = len(i.networkActivity)
	results["suspicious_files"] = len(i.suspiciousFiles)
	results["running"] = i.running
	
	// Count suspicious items
	suspiciousNetworkConns := 0
	for _, conn := range i.networkBaseline {
		if conn.Suspicious {
			suspiciousNetworkConns++
		}
	}
	results["suspicious_network_connections"] = suspiciousNetworkConns
	
	suspiciousProcesses := 0
	for _, proc := range i.processBaseline {
		if proc.Suspicious {
			suspiciousProcesses++
		}
	}
	results["suspicious_processes"] = suspiciousProcesses
	
	return results
}

// IsAvailable checks if intrusion detection capabilities are available
func (i *IntrusionScanner) IsAvailable() bool {
	// Check if we have access to necessary files/directories
	requiredPaths := []string{"/proc", "/var/log"}
	
	for _, path := range requiredPaths {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	
	return true
}

// GetType returns the scanner type
func (i *IntrusionScanner) GetType() string {
	return "intrusion"
}
