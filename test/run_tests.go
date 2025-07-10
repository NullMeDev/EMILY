package test

import (
	"fmt"
	"os"
	"testing"
)

// TestRunner is a test function wrapper for the comprehensive test suite
func TestRunner(t *testing.T) {
	suite := NewTestSuite()
	success := suite.RunAllTests()
	
	if !success {
		t.Fatal("Test suite failed")
	}
}

// RunTestsMain can be called to run tests programmatically
func RunTestsMain() {
	suite := NewTestSuite()
	success := suite.RunAllTests()
	
	if !success {
		fmt.Println("❌ Test suite failed")
		os.Exit(1)
	}
	
	fmt.Println("✅ All tests passed!")
	os.Exit(0)
}
