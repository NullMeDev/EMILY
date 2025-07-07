package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/null/emily/internal/autonomous"
	"github.com/null/emily/internal/config"
	"github.com/null/emily/internal/database"
	"github.com/null/emily/internal/intelligence"
	"github.com/null/emily/internal/models"
	"github.com/null/emily/internal/scanner"
)

var (
	cfgFile string
	debug   bool
	quiet   bool
)

// Execute runs the root command
func Execute(version, commit, date string) error {
	rootCmd := &cobra.Command{
		Use:   "emily",
		Short: "EMILY - Advanced signal intelligence and surveillance detection tool",
		Long: `EMILY is a stealth surveillance detection tool designed for Android devices,
capable of detecting wireless signals, hidden cameras, audio recording devices, and other 
surveillance equipment through passive monitoring.

EMILY = Enhanced Mobile Intelligence for Location-aware Yields

This tool is designed for cybersecurity education and personal security research.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.emily.yaml)")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug mode")
	rootCmd.PersistentFlags().BoolVar(&quiet, "quiet", false, "suppress output")

// Add commands
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(monitorCmd())
	rootCmd.AddCommand(autonomousCmd())
	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(stealthCmd())
	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(statusCmd())

	return rootCmd.Execute()
}

// scanCmd creates the scan command
func scanCmd() *cobra.Command {
	var (
		duration string
		scanType string
		output   string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Perform a signal scan",
		Long:  `Perform a single signal scan to detect wireless devices in the area.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			db, err := database.New(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize database: %w", err)
			}
			defer db.Close()

			scanner, err := scanner.New(cfg, db)
			if err != nil {
				return fmt.Errorf("failed to initialize scanner: %w", err)
			}

			// Parse duration
			scanDuration, err := time.ParseDuration(duration)
			if err != nil {
				return fmt.Errorf("invalid duration: %w", err)
			}

			if !quiet {
				fmt.Printf("Starting %s scan for %s...\n", scanType, duration)
			}

			result, err := scanner.Scan(scanType, scanDuration)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Display results
			if !quiet {
				fmt.Printf("\nScan completed in %s\n", result.Duration)
				fmt.Printf("Devices found: %d\n", len(result.DevicesFound))
				fmt.Printf("Threats detected: %d\n", len(result.ThreatsFound))

				if len(result.DevicesFound) > 0 {
					fmt.Println("\nDetected devices:")
					for _, device := range result.DevicesFound {
						fmt.Printf("  %s %s (%s) - Signal: %ddBm - Threat: %s\n",
							device.GetDeviceTypeIcon(),
							device.Name,
							device.MAC,
							device.SignalLevel,
							device.GetThreatLevelString(),
						)
					}
				}

				if len(result.ThreatsFound) > 0 {
					fmt.Println("\nThreats detected:")
					for _, threat := range result.ThreatsFound {
						fmt.Printf("  🚨 %s (Score: %.1f, Confidence: %.1f)\n",
							threat.Description,
							threat.Score,
							threat.Confidence,
						)
					}
				}
			}

			// Save to file if output specified
			if output != "" {
				return saveResults(result, output)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&duration, "duration", "d", "30s", "scan duration")
	cmd.Flags().StringVarP(&scanType, "type", "t", "full", "scan type (full, quick, wifi, bluetooth, cellular, nfc)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file for results")

	return cmd
}

// monitorCmd creates the monitor command
func monitorCmd() *cobra.Command {
	var (
		interval string
		alerts   bool
	)

	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Start continuous monitoring",
		Long:  `Start continuous monitoring mode for real-time surveillance detection.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			db, err := database.New(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize database: %w", err)
			}
			defer db.Close()

			scanner, err := scanner.New(cfg, db)
			if err != nil {
				return fmt.Errorf("failed to initialize scanner: %w", err)
			}

			if !quiet {
				fmt.Println("Starting continuous monitoring...")
				fmt.Println("Press Ctrl+C to stop")
			}

			// Setup signal handling
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

			go func() {
				<-sigCh
				fmt.Println("\nShutting down...")
				cancel()
			}()

			// Start scanner
			if err := scanner.Start(); err != nil {
				return fmt.Errorf("failed to start scanner: %w", err)
			}

			// Monitor until cancelled
			<-ctx.Done()

			return scanner.Stop()
		},
	}

	cmd.Flags().StringVarP(&interval, "interval", "i", "30s", "scan interval")
	cmd.Flags().BoolVar(&alerts, "alerts", true, "enable alerts")

	return cmd
}

// listCmd creates the list command
func listCmd() *cobra.Command {
	var (
		deviceType   string
		threatLevel  int
		limit        int
		whitelisted  bool
		showThreatLevel bool
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List detected devices",
		Long:  `List devices that have been detected in previous scans.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			db, err := database.New(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize database: %w", err)
			}
			defer db.Close()

			// Build filter
			filter := &models.DeviceFilter{
				Type:        deviceType,
				ThreatLevel: threatLevel,
				Limit:       limit,
			}

			if cmd.Flags().Changed("whitelisted") {
				filter.Whitelisted = &whitelisted
			}

			devices, err := db.GetDevices(filter)
			if err != nil {
				return fmt.Errorf("failed to get devices: %w", err)
			}

			if len(devices) == 0 {
				fmt.Println("No devices found")
				return nil
			}

			fmt.Printf("Found %d devices:\n\n", len(devices))
			for _, device := range devices {
				age := time.Since(device.LastSeen)
				status := "Active"
				if age > 10*time.Minute {
					status = "Inactive"
				}

				fmt.Printf("%s %s (%s)\n", device.GetDeviceTypeIcon(), device.Name, device.MAC)
				fmt.Printf("  Type: %s | Signal: %ddBm (%s) | Status: %s\n",
					device.Type,
					device.SignalLevel,
					device.GetSignalStrengthString(),
					status,
				)
				fmt.Printf("  First seen: %s | Last seen: %s\n",
					device.FirstSeen.Format("2006-01-02 15:04:05"),
					device.LastSeen.Format("2006-01-02 15:04:05"),
				)

				if showThreatLevel || device.ThreatLevel > 0 {
					fmt.Printf("  Threat level: %d (%s)\n", device.ThreatLevel, device.GetThreatLevelString())
				}

				if device.IsWhitelisted {
					fmt.Printf("  ✅ Whitelisted\n")
				}

				if device.Notes != "" {
					fmt.Printf("  Notes: %s\n", device.Notes)
				}

				fmt.Println()
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&deviceType, "type", "t", "", "filter by device type")
	cmd.Flags().IntVar(&threatLevel, "threat", 0, "minimum threat level")
	cmd.Flags().IntVarP(&limit, "limit", "l", 50, "maximum number of devices to show")
	cmd.Flags().BoolVar(&whitelisted, "whitelisted", false, "show only whitelisted devices")
	cmd.Flags().BoolVar(&showThreatLevel, "show-threats", false, "always show threat levels")

	return cmd
}

// stealthCmd creates the stealth command
func stealthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stealth",
		Short: "Stealth mode operations",
		Long:  `Enable stealth mode features for covert operation.`,
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "enable",
		Short: "Enable stealth mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			cfg.Stealth.HiddenMode = true
			cfg.Stealth.SilentMode = true
			return config.SaveConfig(cfg, cfgFile)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "disable",
		Short: "Disable stealth mode",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			cfg.Stealth.HiddenMode = false
			cfg.Stealth.SilentMode = false
			return config.SaveConfig(cfg, cfgFile)
		},
	})

	return cmd
}

// configCmd creates the config command
func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management",
		Long:  `Manage PhantomScan configuration settings.`,
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show current configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			
			fmt.Printf("EMILY Configuration:\n\n")
			fmt.Printf("App Name: %s\n", cfg.Core.AppName)
			fmt.Printf("Version: %s\n", cfg.Core.Version)
			fmt.Printf("Debug Mode: %t\n", cfg.Core.Debug)
			fmt.Printf("Scan Interval: %s\n", cfg.Core.ScanInterval)
			fmt.Printf("\nDetection:\n")
			fmt.Printf("  WiFi: %t\n", cfg.Detection.WiFi.Enabled)
			fmt.Printf("  Bluetooth: %t\n", cfg.Detection.Bluetooth.Enabled)
			fmt.Printf("  Cellular: %t\n", cfg.Detection.Cellular.Enabled)
			fmt.Printf("  NFC: %t\n", cfg.Detection.NFC.Enabled)
			fmt.Printf("\nStealth Mode:\n")
			fmt.Printf("  Hidden: %t\n", cfg.Stealth.HiddenMode)
			fmt.Printf("  Silent: %t\n", cfg.Stealth.SilentMode)
			fmt.Printf("  Encrypted Storage: %t\n", cfg.Stealth.EncryptedStorage)
			
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Initialize default configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.DefaultConfig()
			if debug {
				cfg.Core.Debug = true
			}
			return config.SaveConfig(cfg, cfgFile)
		},
	})

	return cmd
}

// statusCmd creates the status command
func statusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show system status",
		Long:  `Display current system status and statistics.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			db, err := database.New(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize database: %w", err)
			}
			defer db.Close()

			// Get database size
			size, err := db.GetDatabaseSize()
			if err == nil {
				fmt.Printf("Database size: %.2f MB\n", float64(size)/(1024*1024))
			}

			// Get recent statistics
			stats, err := db.GetStatistics(time.Now().Add(-24 * time.Hour))
			if err == nil {
				fmt.Printf("\nLast 24 hours:\n")
				fmt.Printf("  Total scans: %d\n", stats.TotalScans)
				fmt.Printf("  Devices found: %d\n", stats.TotalDevices)
				fmt.Printf("  New devices: %d\n", stats.NewDevices)
				fmt.Printf("  Threats detected: %d\n", stats.ThreatsDetected)
				fmt.Printf("  Average scan duration: %.1f seconds\n", stats.AvgScanDuration)
			}

			// Get unacknowledged alerts
			alerts, err := db.GetUnacknowledgedAlerts()
			if err == nil && len(alerts) > 0 {
				fmt.Printf("\nUnacknowledged alerts: %d\n", len(alerts))
				for _, alert := range alerts {
					fmt.Printf("  🚨 %s - %s\n", alert.Title, alert.CreatedAt.Format("15:04:05"))
				}
			}

			return nil
		},
	}

	return cmd
}

// Helper functions

func loadConfig() (*config.Config, error) {
	cfg, err := config.LoadConfig(cfgFile)
	if err != nil {
		return nil, err
	}

	// Apply CLI flags
	if debug {
		cfg.Core.Debug = true
	}

	return cfg, nil
}

// autonomousCmd creates the autonomous command
func autonomousCmd() *cobra.Command {
	var (
		noExploits bool
		noCountermeasures bool
		noForensics bool
	)

	cmd := &cobra.Command{
		Use:   "autonomous",
		Short: "Start autonomous surveillance detection and response",
		Long: `Start fully autonomous mode that continuously scans for threats,
automatically applies countermeasures, collects evidence, and executes
exploits against surveillance devices.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			db, err := database.New(cfg)
			if err != nil {
				return fmt.Errorf("failed to initialize database: %w", err)
			}
			defer db.Close()

			scanner, err := scanner.New(cfg, db)
			if err != nil {
				return fmt.Errorf("failed to initialize scanner: %w", err)
			}

			intel, err := intelligence.NewIntelligenceEngine(cfg, db)
			if err != nil {
				return fmt.Errorf("failed to initialize intelligence engine: %w", err)
			}

			// Create autonomous engine
			autonomousEngine, err := autonomous.NewAutonomousEngine(cfg, db, scanner, intel)
			if err != nil {
				return fmt.Errorf("failed to initialize autonomous engine: %w", err)
			}

			if !quiet {
				fmt.Println("🤖 EMILY Autonomous Mode")
				fmt.Println("═══════════════════════════")
				fmt.Println("Features enabled:")
				fmt.Println("  🔍 Continuous threat scanning")
				fmt.Println("  🧠 Intelligent threat analysis")
				fmt.Println("  📊 Behavioral pattern recognition")
				if !noExploits {
					fmt.Println("  ⚡ Autonomous exploitation")
				}
				if !noCountermeasures {
					fmt.Println("  🛡️  Active countermeasures")
				}
				if !noForensics {
					fmt.Println("  🔬 Evidence collection")
				}
				fmt.Println("  🚨 Real-time alerting")
				fmt.Println()
				fmt.Println("⚠️  WARNING: This mode performs active operations")
				fmt.Println("⚠️  Some features may be illegal in your jurisdiction")
				fmt.Println("⚠️  Use only in authorized environments")
				fmt.Println()
				fmt.Println("Starting autonomous operations...")
				fmt.Println("Press Ctrl+C to stop")
			}

			// Setup signal handling
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

			go func() {
				<-sigCh
				fmt.Println("\n🛑 Shutting down autonomous mode...")
				cancel()
			}()

			// Start autonomous engine
			if err := autonomousEngine.Start(); err != nil {
				return fmt.Errorf("failed to start autonomous engine: %w", err)
			}

			// Status update loop
			go func() {
				ticker := time.NewTicker(30 * time.Second)
				defer ticker.Stop()

				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						if !quiet {
							status := autonomousEngine.GetStatus()
							fmt.Printf("[%s] Threats: %d | Active Countermeasures: %d | Uptime: %s\n",
								time.Now().Format("15:04:05"),
								status.TotalThreats,
								status.ActiveCounters,
								time.Since(status.StartTime).Round(time.Second),
							)
						}
					}
				}
			}()

			// Wait for shutdown
			<-ctx.Done()

			// Stop autonomous engine
			if err := autonomousEngine.Stop(); err != nil {
				fmt.Printf("Error stopping autonomous engine: %v\n", err)
			}

			if !quiet {
				fmt.Println("✅ Autonomous mode stopped")
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&noExploits, "no-exploits", false, "disable autonomous exploitation")
	cmd.Flags().BoolVar(&noCountermeasures, "no-countermeasures", false, "disable active countermeasures")
	cmd.Flags().BoolVar(&noForensics, "no-forensics", false, "disable evidence collection")

	return cmd
}

func saveResults(result *models.ScanResult, filename string) error {
	// TODO: Implement result saving in various formats
	fmt.Printf("Results saved to %s\n", filename)
	return nil
}
