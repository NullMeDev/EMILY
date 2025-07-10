package main

import (
	"fmt"
	"os"
)

func main() {
	suite := NewTestSuite()
	success := suite.RunAllTests()
	
	if !success {
		fmt.Println("❌ Test suite failed")
		os.Exit(1)
	}
	
	fmt.Println("✅ All tests passed!")
	os.Exit(0)
}
