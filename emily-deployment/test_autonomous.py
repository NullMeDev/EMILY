#!/usr/bin/env python3

"""
EMILY Autonomous Mode Test Script
Tests autonomous surveillance detection functionality
"""

import subprocess
import time
import sys
import os

def test_autonomous_mode():
    """Test autonomous mode functionality"""
    print("🤖 Testing EMILY Autonomous Mode")
    print("=" * 40)
    
    # Check if emily binary exists
    emily_bin = "./bin/emily"
    if not os.path.exists(emily_bin):
        print("❌ EMILY binary not found")
        return False
    
    try:
        # Test autonomous mode startup
        print("Testing autonomous mode startup...")
        process = subprocess.Popen([
            emily_bin, "autonomous", 
            "--no-exploits", 
            "--no-countermeasures",
            "--interval", "5"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Let it run for 10 seconds
        time.sleep(10)
        
        # Check if it's still running
        if process.poll() is None:
            print("✅ Autonomous mode started successfully")
            process.terminate()
            process.wait()
            return True
        else:
            print("❌ Autonomous mode failed to start")
            return False
            
    except Exception as e:
        print(f"❌ Error testing autonomous mode: {e}")
        return False

def main():
    """Main test function"""
    print("EMILY Autonomous Mode Test")
    print("=" * 50)
    
    success = test_autonomous_mode()
    
    if success:
        print("\n✅ Autonomous mode test PASSED")
        sys.exit(0)
    else:
        print("\n❌ Autonomous mode test FAILED")
        sys.exit(1)

if __name__ == "__main__":
    main()
