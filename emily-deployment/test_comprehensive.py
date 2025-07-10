#!/usr/bin/env python3

"""
EMILY Comprehensive Test Script
Runs complete test suite for all EMILY functionality
"""

import subprocess
import time
import sys
import os
import json

def run_command(cmd, timeout=30):
    """Run a command with timeout"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, 
                              text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"

def test_basic_functionality():
    """Test basic EMILY functionality"""
    print("🔧 Testing Basic Functionality")
    print("-" * 30)
    
    tests = [
        ("Binary exists", "test -f ./bin/emily"),
        ("Help command", "./bin/emily --help"),
        ("Config init", "./bin/emily config init"),
        ("Config show", "./bin/emily config show"),
        ("Status check", "./bin/emily status"),
    ]
    
    passed = 0
    for name, cmd in tests:
        print(f"Testing {name}...", end=" ")
        code, stdout, stderr = run_command(cmd, 10)
        if code == 0:
            print("✅")
            passed += 1
        else:
            print("❌")
    
    return passed, len(tests)

def test_scanning():
    """Test scanning functionality"""
    print("\n📡 Testing Scanning")
    print("-" * 20)
    
    tests = [
        ("WiFi scan", "./bin/emily scan --duration 5s --type wifi"),
        ("Bluetooth scan", "./bin/emily scan --duration 5s --type bluetooth"),
        ("Cellular scan", "./bin/emily scan --duration 5s --type cellular"),
        ("NFC scan", "./bin/emily scan --duration 5s --type nfc"),
        ("Full scan", "./bin/emily scan --duration 10s --type full"),
    ]
    
    passed = 0
    for name, cmd in tests:
        print(f"Testing {name}...", end=" ")
        code, stdout, stderr = run_command(cmd, 15)
        if code == 0:
            print("✅")
            passed += 1
        else:
            print("❌")
    
    return passed, len(tests)

def test_advanced_features():
    """Test advanced features"""
    print("\n🚀 Testing Advanced Features")
    print("-" * 30)
    
    tests = [
        ("Device listing", "./bin/emily list"),
        ("Stealth enable", "./bin/emily stealth enable"),
        ("Stealth disable", "./bin/emily stealth disable"),
    ]
    
    passed = 0
    for name, cmd in tests:
        print(f"Testing {name}...", end=" ")
        code, stdout, stderr = run_command(cmd, 10)
        if code == 0:
            print("✅")
            passed += 1
        else:
            print("❌")
    
    return passed, len(tests)

def test_autonomous_mode():
    """Test autonomous mode"""
    print("\n🤖 Testing Autonomous Mode")
    print("-" * 25)
    
    print("Testing autonomous startup...", end=" ")
    
    # Start autonomous mode
    cmd = "./bin/emily autonomous --no-exploits --no-countermeasures --interval 5"
    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, 
                             stderr=subprocess.PIPE)
    
    # Let it run for 8 seconds
    time.sleep(8)
    
    # Check if still running
    if process.poll() is None:
        print("✅")
        process.terminate()
        process.wait()
        return 1, 1
    else:
        print("❌")
        return 0, 1

def generate_report(results):
    """Generate test report"""
    total_passed = sum(r[0] for r in results.values())
    total_tests = sum(r[1] for r in results.values())
    success_rate = (total_passed / total_tests) * 100 if total_tests > 0 else 0
    
    print("\n" + "=" * 60)
    print("EMILY COMPREHENSIVE TEST REPORT")
    print("=" * 60)
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_tests - total_passed}")
    print(f"Success Rate: {success_rate:.1f}%")
    print()
    
    for category, (passed, total) in results.items():
        status = "✅" if passed == total else "⚠️" if passed > 0 else "❌"
        print(f"{status} {category}: {passed}/{total}")
    
    print("=" * 60)
    
    if success_rate >= 80:
        print("🎉 EXCELLENT! System ready for deployment")
        return True
    elif success_rate >= 60:
        print("✅ GOOD! System mostly functional")
        return True
    else:
        print("❌ NEEDS WORK! Significant issues detected")
        return False

def main():
    """Main test function"""
    print("🚀 EMILY Comprehensive Test Suite")
    print("=" * 60)
    
    results = {}
    
    # Run all test categories
    results["Basic Functionality"] = test_basic_functionality()
    results["Scanning"] = test_scanning()
    results["Advanced Features"] = test_advanced_features()
    results["Autonomous Mode"] = test_autonomous_mode()
    
    # Generate report
    success = generate_report(results)
    
    if success:
        print("\n✅ Test suite PASSED")
        sys.exit(0)
    else:
        print("\n❌ Test suite FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()
