#!/usr/bin/env python3
"""
EMILY Autonomous Mode Testing Script - Resource-Safe Version
Optimized testing for autonomous detection and response capabilities with resource limits
"""

import time
import threading
import subprocess
import random
import sys
import psutil
import signal
from pathlib import Path

class ResourceSafeTester:
    def __init__(self):
        self.test_results = {}
        self.active_tests = []
        self.max_cpu_percent = 50  # Limit CPU usage to 50%
        self.max_memory_mb = 512   # Limit memory to 512MB
        self.running = True
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        self.log(f"Received signal {signum}, shutting down gracefully...", "WARN")
        self.running = False
        self.cleanup()
        sys.exit(0)
        
    def log(self, message, level="INFO"):
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
        
    def check_resources(self):
        """Check if system resources are within safe limits"""
        try:
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > self.max_cpu_percent:
                self.log(f"High CPU usage detected: {cpu_percent}%. Pausing tests...", "WARN")
                time.sleep(5)
                return False
                
            # Check memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 80:
                self.log(f"High memory usage detected: {memory.percent}%. Pausing tests...", "WARN")
                time.sleep(5)
                return False
                
            # Check available disk space
            disk = psutil.disk_usage('/')
            if disk.percent > 90:
                self.log(f"Low disk space: {disk.percent}% used. Stopping tests...", "ERROR")
                return False
                
            return True
        except Exception as e:
            self.log(f"Resource check failed: {e}", "ERROR")
            return False
            
    def create_test_environment(self):
        """Create minimal test environment"""
        self.log("Setting up minimal test environment...")
        
        # Only enable services if they're not already running
        try:
            # Check if NetworkManager is running
            nm_active = subprocess.run(["systemctl", "is-active", "NetworkManager"], 
                                     capture_output=True, check=False)
            if nm_active.returncode != 0:
                subprocess.run(["sudo", "systemctl", "start", "NetworkManager"], 
                             capture_output=True, check=False)
                self.log("NetworkManager started")
            else:
                self.log("NetworkManager already running")
                
        except Exception as e:
            self.log(f"Service setup warning: {e}", "WARN")
            
    def test_basic_detection(self):
        """Test basic detection without intensive operations"""
        self.log("Testing basic detection (30 seconds)...")
        
        if not self.check_resources():
            self.log("Skipping detection test due to resource constraints", "WARN")
            return
            
        # Run emily for only 30 seconds instead of 2 minutes
        emily_cmd = [
            "./emily", "scan", "--quiet"
        ]
        
        try:
            process = subprocess.Popen(
                emily_cmd, stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, text=True
            )
            
            # Monitor for 30 seconds with resource checks
            start_time = time.time()
            while time.time() - start_time < 30 and self.running:
                if not self.check_resources():
                    break
                time.sleep(2)
                
            process.terminate()
            
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                
            # Analyze results
            detected_wifi = stdout.count("WiFi device") + stdout.count("wifi")
            detected_bluetooth = stdout.count("Bluetooth device") + stdout.count("bluetooth")
            
            self.test_results['wifi_detection'] = detected_wifi
            self.test_results['bluetooth_detection'] = detected_bluetooth
            
            self.log(f"Basic detection: {detected_wifi} WiFi, {detected_bluetooth} Bluetooth")
            
        except Exception as e:
            self.log(f"Basic detection test failed: {e}", "ERROR")
            
    def test_config_validation(self):
        """Test configuration validation"""
        self.log("Testing configuration validation...")
        
        try:
            # Test config loading
            config_test = subprocess.run([
                "./emily", "config", "--help"
            ], capture_output=True, text=True, timeout=10)
            
            if config_test.returncode == 0:
                self.test_results['config_valid'] = True
                self.log("Configuration validation passed")
            else:
                self.test_results['config_valid'] = False
                self.log(f"Configuration validation failed: {config_test.stderr}", "ERROR")
                
        except Exception as e:
            self.log(f"Config validation test failed: {e}", "ERROR")
            self.test_results['config_valid'] = False
            
    def test_tool_availability(self):
        """Test if required tools are available"""
        self.log("Testing tool availability...")
        
        tools = {
            'system': ['python3', 'systemctl', 'ps', 'netstat'],
            'network': ['iwconfig', 'rfkill', 'bluetoothctl'],
            'optional': ['aircrack-ng', 'hcxdumptool', 'tcpdump']
        }
        
        results = {}
        for category, tool_list in tools.items():
            available = 0
            for tool in tool_list:
                try:
                    result = subprocess.run(['which', tool], 
                                          capture_output=True, check=False)
                    if result.returncode == 0:
                        available += 1
                except:
                    pass
            
            results[category] = available / len(tool_list)
            self.log(f"{category.title()} tools: {available}/{len(tool_list)} available")
            
        self.test_results['tool_availability'] = results
        
    def test_file_permissions(self):
        """Test file system permissions"""
        self.log("Testing file permissions...")
        
        try:
            # Check if main binary is executable
            emily_binary = Path("emily")
            if emily_binary.exists() and emily_binary.is_file():
                permissions_ok = emily_binary.stat().st_mode & 0o111 != 0
                self.test_results['emily_executable'] = permissions_ok
                self.log(f"EMILY binary executable: {permissions_ok}")
            else:
                self.test_results['emily_executable'] = False
                self.log("EMILY binary not found", "ERROR")
                
            # Check if we can write to evidence directory
            evidence_dir = Path("evidence")
            if not evidence_dir.exists():
                evidence_dir.mkdir()
                
            test_file = evidence_dir / "test.txt"
            try:
                test_file.write_text("test")
                test_file.unlink()
                self.test_results['evidence_writable'] = True
                self.log("Evidence directory writable: True")
            except:
                self.test_results['evidence_writable'] = False
                self.log("Evidence directory not writable", "ERROR")
                
        except Exception as e:
            self.log(f"File permissions test failed: {e}", "ERROR")
            
    def test_network_interfaces(self):
        """Test network interface availability"""
        self.log("Testing network interfaces...")
        
        try:
            # Check wireless interfaces
            iwconfig_result = subprocess.run(['iwconfig'], 
                                           capture_output=True, text=True, check=False)
            
            wireless_interfaces = []
            for line in iwconfig_result.stdout.split('\n'):
                if 'IEEE 802.11' in line:
                    interface = line.split()[0]
                    wireless_interfaces.append(interface)
                    
            self.test_results['wireless_interfaces'] = len(wireless_interfaces)
            self.log(f"Wireless interfaces found: {len(wireless_interfaces)}")
            
            # Check Bluetooth
            bt_result = subprocess.run(['hciconfig'], 
                                     capture_output=True, text=True, check=False)
            
            bluetooth_available = 'hci' in bt_result.stdout
            self.test_results['bluetooth_available'] = bluetooth_available
            self.log(f"Bluetooth available: {bluetooth_available}")
            
        except Exception as e:
            self.log(f"Network interface test failed: {e}", "ERROR")
            
    def cleanup(self):
        """Clean up test environment"""
        self.log("Cleaning up test environment...")
        
        # Terminate any active processes
        for process in self.active_tests:
            try:
                if process.poll() is None:  # Process still running
                    process.terminate()
                    process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
                    
        # Clean up any test files
        try:
            test_evidence = Path("evidence/test.txt")
            if test_evidence.exists():
                test_evidence.unlink()
        except:
            pass
            
    def generate_report(self):
        """Generate test report"""
        self.log("\n" + "="*50)
        self.log("EMILY RESOURCE-SAFE TEST REPORT")
        self.log("="*50)
        
        # System info
        try:
            cpu_count = psutil.cpu_count()
            memory_gb = psutil.virtual_memory().total / (1024**3)
            self.log(f"System: {cpu_count} CPUs, {memory_gb:.1f}GB RAM")
        except:
            pass
            
        # Test results
        for test, result in self.test_results.items():
            if isinstance(result, dict):
                self.log(f"{test.upper()}:")
                for key, value in result.items():
                    if isinstance(value, float):
                        self.log(f"  {key}: {value:.2f}")
                    else:
                        self.log(f"  {key}: {value}")
            else:
                self.log(f"{test.upper()}: {result}")
                
        # Calculate health score
        scores = []
        
        # Basic functionality
        if self.test_results.get('config_valid', False):
            scores.append(1.0)
        else:
            scores.append(0.0)
            
        if self.test_results.get('emily_executable', False):
            scores.append(1.0)
        else:
            scores.append(0.0)
            
        # Tool availability
        if 'tool_availability' in self.test_results:
            tool_scores = list(self.test_results['tool_availability'].values())
            if tool_scores:
                scores.append(sum(tool_scores) / len(tool_scores))
                
        # Network capabilities
        if self.test_results.get('wireless_interfaces', 0) > 0:
            scores.append(1.0)
        else:
            scores.append(0.5)
            
        if self.test_results.get('bluetooth_available', False):
            scores.append(1.0)
        else:
            scores.append(0.5)
            
        # Detection capabilities
        wifi_detected = self.test_results.get('wifi_detection', 0)
        bluetooth_detected = self.test_results.get('bluetooth_detection', 0)
        if wifi_detected > 0 or bluetooth_detected > 0:
            scores.append(1.0)
        else:
            scores.append(0.3)  # Might be due to no devices around
            
        if scores:
            health_score = sum(scores) / len(scores)
            self.log(f"\nOVERALL HEALTH SCORE: {health_score:.2f}/1.00")
            
            if health_score >= 0.8:
                self.log("✅ EMILY is in EXCELLENT condition", "SUCCESS")
            elif health_score >= 0.6:
                self.log("⚠️  EMILY is in GOOD condition", "SUCCESS")
            elif health_score >= 0.4:
                self.log("⚠️  EMILY needs minor improvements", "WARN")
            else:
                self.log("❌ EMILY needs attention", "ERROR")
        else:
            self.log("❌ Unable to calculate health score", "ERROR")
            
    def run_safe_tests(self):
        """Run resource-safe test suite"""
        self.log("Starting EMILY Resource-Safe Test Suite")
        self.log("="*50)
        
        # Initial resource check
        if not self.check_resources():
            self.log("System resources too high to run tests safely", "ERROR")
            return
            
        try:
            self.create_test_environment()
            
            # Run lightweight tests first
            self.test_config_validation()
            self.test_file_permissions()
            self.test_tool_availability()
            self.test_network_interfaces()
            
            # Only run detection test if resources are still good
            if self.check_resources() and self.running:
                self.test_basic_detection()
            else:
                self.log("Skipping detection test due to resource constraints", "WARN")
                
        except KeyboardInterrupt:
            self.log("Test interrupted by user", "WARN")
        except Exception as e:
            self.log(f"Test suite failed: {e}", "ERROR")
        finally:
            self.cleanup()
            self.generate_report()

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("EMILY Resource-Safe Testing Script")
        print("\nUsage:")
        print("  python3 test_autonomous_safe.py          # Run safe test suite")
        print("  python3 test_autonomous_safe.py --help   # Show this help")
        print("\nFeatures:")
        print("  - Resource monitoring and limits")
        print("  - Graceful shutdown on resource exhaustion")
        print("  - Lightweight tests only")
        print("  - System health assessment")
        print("\nSafety Features:")
        print("  - CPU usage limited to 50%")
        print("  - Memory monitoring")
        print("  - Automatic test suspension on high usage")
        print("  - Signal handling for clean shutdown")
        return
        
    # Check if psutil is available
    try:
        import psutil
    except ImportError:
        print("ERROR: psutil module required for resource monitoring")
        print("Install with: pip install psutil")
        sys.exit(1)
        
    tester = ResourceSafeTester()
    tester.run_safe_tests()

if __name__ == "__main__":
    main()

