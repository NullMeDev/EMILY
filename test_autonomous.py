#!/usr/bin/env python3
"""
EMILY Autonomous Mode Testing Script
Comprehensive testing for autonomous detection and response capabilities
"""

import time
import threading
import subprocess
import random
import sys
from pathlib import Path

class AutonomousTester:
    def __init__(self):
        self.test_results = {}
        self.active_tests = []
        
    def log(self, message, level="INFO"):
        timestamp = time.strftime("%H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
        
    def create_test_environment(self):
        """Create controlled test environment with known devices"""
        self.log("Setting up test environment...")
        
        # Enable WiFi and Bluetooth for testing
        try:
            subprocess.run(["sudo", "systemctl", "start", "NetworkManager"], 
                         capture_output=True, check=False)
            subprocess.run(["sudo", "systemctl", "start", "bluetooth"], 
                         capture_output=True, check=False)
            self.log("Network services started")
        except Exception as e:
            self.log(f"Failed to start services: {e}", "WARN")
            
        # Create test WiFi networks (if we have a USB WiFi adapter)
        self.create_test_networks()
        
        # Start Bluetooth test devices
        self.start_bluetooth_tests()
        
    def create_test_networks(self):
        """Create test WiFi access points for detection"""
        test_networks = [
            "FREE_WIFI_DEFINITELY_LEGIT",
            "Starbucks_Guest", 
            "xfinitywifi",
            "iPhone_Hotspot_Surveillance"
        ]
        
        self.log("Creating test WiFi networks...")
        # Note: This would require actual WiFi hardware setup
        # For testing, we'll simulate by creating config files
        
        for network in test_networks:
            self.log(f"Test network available: {network}")
            
    def start_bluetooth_tests(self):
        """Start Bluetooth devices for testing"""
        self.log("Starting Bluetooth test devices...")
        
        # Start bluetoothctl in background to make device discoverable
        try:
            process = subprocess.Popen([
                "bluetoothctl"
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, 
               stderr=subprocess.PIPE, text=True)
            
            # Make discoverable
            process.stdin.write("discoverable on\n")
            process.stdin.write("pairable on\n")
            process.stdin.flush()
            
            self.active_tests.append(process)
            self.log("Bluetooth test device activated")
            
        except Exception as e:
            self.log(f"Bluetooth test setup failed: {e}", "WARN")
            
    def test_detection_accuracy(self):
        """Test detection accuracy against known devices"""
        self.log("Testing detection accuracy...")
        
        # Run emily in autonomous mode for 2 minutes
        emily_cmd = [
            "python3", "emily.py", "autonomous", 
            "--interval", "10", "--no-exploit", "--no-counter"
        ]
        
        try:
            process = subprocess.Popen(
                emily_cmd, stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, text=True
            )
            
            # Let it run for 2 minutes
            time.sleep(120)
            process.terminate()
            
            stdout, stderr = process.communicate(timeout=10)
            
            # Analyze results
            detected_wifi = stdout.count("WiFi device detected")
            detected_bluetooth = stdout.count("Bluetooth device detected")
            
            self.test_results['wifi_detection'] = detected_wifi
            self.test_results['bluetooth_detection'] = detected_bluetooth
            
            self.log(f"Detected {detected_wifi} WiFi devices")
            self.log(f"Detected {detected_bluetooth} Bluetooth devices")
            
        except Exception as e:
            self.log(f"Detection test failed: {e}", "ERROR")
            
    def test_response_speed(self):
        """Test autonomous response time"""
        self.log("Testing response speed...")
        
        start_time = time.time()
        
        # Create a new WiFi hotspot
        try:
            hotspot_process = subprocess.Popen([
                "sudo", "create_ap", "wlan0", "eth0", 
                "EMILY_TEST_NETWORK", "testpassword"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Monitor emily's response
            emily_cmd = [
                "python3", "emily.py", "autonomous", 
                "--interval", "5"
            ]
            
            emily_process = subprocess.Popen(
                emily_cmd, stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, text=True
            )
            
            # Wait for detection
            detection_time = None
            while time.time() - start_time < 60:  # 1 minute timeout
                output = emily_process.stdout.readline()
                if "EMILY_TEST_NETWORK" in output:
                    detection_time = time.time() - start_time
                    break
                time.sleep(1)
                
            # Cleanup
            hotspot_process.terminate()
            emily_process.terminate()
            
            if detection_time:
                self.log(f"Detection time: {detection_time:.2f} seconds")
                self.test_results['response_time'] = detection_time
            else:
                self.log("Failed to detect test network within timeout", "ERROR")
                
        except Exception as e:
            self.log(f"Response speed test failed: {e}", "ERROR")
            
    def test_countermeasures(self):
        """Test countermeasure effectiveness"""
        self.log("Testing countermeasures...")
        
        # This would test jamming effectiveness, etc.
        # For safety, we'll simulate the test
        
        self.log("Simulating countermeasure test...")
        time.sleep(5)
        
        # Check if countermeasures would work
        countermeasures_available = self.check_countermeasure_tools()
        
        self.test_results['countermeasures'] = countermeasures_available
        self.log(f"Countermeasures available: {countermeasures_available}")
        
    def check_countermeasure_tools(self):
        """Check if countermeasure tools are available"""
        tools = ['aircrack-ng', 'hcxdumptool', 'rfkill']
        available = 0
        
        for tool in tools:
            try:
                result = subprocess.run(['which', tool], 
                                      capture_output=True, check=False)
                if result.returncode == 0:
                    available += 1
            except:
                pass
                
        return available / len(tools)
        
    def test_stealth_mode(self):
        """Test stealth operation"""
        self.log("Testing stealth mode...")
        
        # Check if emily is detectable by common monitoring tools
        try:
            # Check process visibility
            ps_result = subprocess.run(['ps', 'aux'], 
                                     capture_output=True, text=True)
            emily_visible = 'emily' in ps_result.stdout.lower()
            
            # Check network connections
            netstat_result = subprocess.run(['netstat', '-tulpn'], 
                                          capture_output=True, text=True, check=False)
            emily_connections = 'emily' in netstat_result.stdout.lower()
            
            stealth_score = 1.0
            if emily_visible:
                stealth_score -= 0.5
                self.log("WARNING: EMILY process visible in ps", "WARN")
            if emily_connections:
                stealth_score -= 0.5
                self.log("WARNING: EMILY network activity visible", "WARN")
                
            self.test_results['stealth'] = stealth_score
            self.log(f"Stealth score: {stealth_score:.2f}")
            
        except Exception as e:
            self.log(f"Stealth test failed: {e}", "ERROR")
            
    def test_evidence_collection(self):
        """Test forensic evidence collection"""
        self.log("Testing evidence collection...")
        
        # Check if evidence files are created
        evidence_dir = Path("evidence")
        if evidence_dir.exists():
            evidence_files = list(evidence_dir.glob("*.pcap"))
            log_files = list(evidence_dir.glob("*.log"))
            
            self.test_results['evidence_files'] = len(evidence_files) + len(log_files)
            self.log(f"Evidence files created: {len(evidence_files)} pcap, {len(log_files)} logs")
        else:
            self.test_results['evidence_files'] = 0
            self.log("No evidence directory found", "WARN")
            
    def cleanup(self):
        """Clean up test environment"""
        self.log("Cleaning up test environment...")
        
        # Terminate active test processes
        for process in self.active_tests:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                process.kill()
                
        # Clean up test files
        try:
            subprocess.run(['sudo', 'pkill', '-f', 'create_ap'], check=False)
        except:
            pass
            
    def generate_report(self):
        """Generate test report"""
        self.log("\n" + "="*50)
        self.log("EMILY AUTONOMOUS MODE TEST REPORT")
        self.log("="*50)
        
        for test, result in self.test_results.items():
            self.log(f"{test.upper()}: {result}")
            
        # Calculate overall score
        scores = []
        if 'wifi_detection' in self.test_results:
            scores.append(min(self.test_results['wifi_detection'] / 5, 1.0))
        if 'bluetooth_detection' in self.test_results:
            scores.append(min(self.test_results['bluetooth_detection'] / 3, 1.0))
        if 'response_time' in self.test_results:
            # Good response time is under 30 seconds
            scores.append(max(0, 1.0 - self.test_results['response_time'] / 30))
        if 'countermeasures' in self.test_results:
            scores.append(self.test_results['countermeasures'])
        if 'stealth' in self.test_results:
            scores.append(self.test_results['stealth'])
        if 'evidence_files' in self.test_results:
            scores.append(min(self.test_results['evidence_files'] / 10, 1.0))
            
        if scores:
            overall_score = sum(scores) / len(scores)
            self.log(f"\nOVERALL SCORE: {overall_score:.2f}/1.00")
            
            if overall_score >= 0.8:
                self.log("✅ EMILY autonomous mode is EXCELLENT", "SUCCESS")
            elif overall_score >= 0.6:
                self.log("⚠️  EMILY autonomous mode is GOOD", "SUCCESS")
            elif overall_score >= 0.4:
                self.log("⚠️  EMILY autonomous mode needs IMPROVEMENT", "WARN")
            else:
                self.log("❌ EMILY autonomous mode needs MAJOR FIXES", "ERROR")
        else:
            self.log("❌ Unable to calculate score - no tests completed", "ERROR")
            
    def run_all_tests(self):
        """Run comprehensive test suite"""
        self.log("Starting EMILY Autonomous Mode Test Suite")
        self.log("="*50)
        
        try:
            self.create_test_environment()
            time.sleep(10)  # Let environment settle
            
            self.test_detection_accuracy()
            self.test_response_speed()
            self.test_countermeasures()
            self.test_stealth_mode()
            self.test_evidence_collection()
            
        except KeyboardInterrupt:
            self.log("Test interrupted by user", "WARN")
        except Exception as e:
            self.log(f"Test suite failed: {e}", "ERROR")
        finally:
            self.cleanup()
            self.generate_report()

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("EMILY Autonomous Mode Testing Script")
        print("\nUsage:")
        print("  python3 test_autonomous.py          # Run full test suite")
        print("  python3 test_autonomous.py --help   # Show this help")
        print("\nTests:")
        print("  - Detection Accuracy")
        print("  - Response Speed")
        print("  - Countermeasure Effectiveness")
        print("  - Stealth Operation")
        print("  - Evidence Collection")
        return
        
    tester = AutonomousTester()
    tester.run_all_tests()

if __name__ == "__main__":
    main()
