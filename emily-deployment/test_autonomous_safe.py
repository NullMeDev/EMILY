#!/usr/bin/env python3

"""
EMILY Safe Autonomous Mode Test Script
Tests autonomous mode with safety restrictions enabled
"""

import subprocess
import time
import sys
import os

def test_safe_autonomous_mode():
    """Test safe autonomous mode functionality"""
    print("🛡️  Testing EMILY Safe Autonomous Mode")
    print("=" * 45)
    
    # Check if emily binary exists
    emily_bin = "./bin/emily"
    if not os.path.exists(emily_bin):
        print("❌ EMILY binary not found")
        return False
    
    try:
        # Test safe autonomous mode
        print("Testing safe autonomous mode...")
        process = subprocess.Popen([
            emily_bin, "autonomous", 
            "--no-exploits", 
            "--no-countermeasures",
            "--evidence-only",
            "--interval", "3"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Let it run for 8 seconds
        time.sleep(8)
        
        # Check if it's running
        if process.poll() is None:
            print("✅ Safe autonomous mode working correctly")
            process.terminate()
            process.wait()
            return True
        else:
            stdout, stderr = process.communicate()
            print(f"❌ Safe autonomous mode failed: {stderr.decode()}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing safe autonomous mode: {e}")
        return False

def main():
    """Main test function"""
    print("EMILY Safe Autonomous Mode Test")
    print("=" * 55)
    
    success = test_safe_autonomous_mode()
    
    if success:
        print("\n✅ Safe autonomous mode test PASSED")
        sys.exit(0)
    else:
        print("\n❌ Safe autonomous mode test FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()
