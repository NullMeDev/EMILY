package main

import "fmt"

const (
	// Version represents the current version of EMILY
	Version = "1.0.0"
	
	// BuildDate represents when this version was built
	BuildDate = "2025-07-10"
	
	// GitCommit represents the git commit hash this version was built from
	GitCommit = "a753988"
	
	// ProjectName is the name of the project
	ProjectName = "EMILY"
	
	// ProjectDescription is a short description of the project
	ProjectDescription = "Enhanced Mobile Intelligence for Location-aware Yields"
)

// GetVersionInfo returns formatted version information
func GetVersionInfo() string {
	return fmt.Sprintf("%s v%s (built %s, commit %s)", 
		ProjectName, Version, BuildDate, GitCommit)
}

// GetFullVersionInfo returns detailed version information
func GetFullVersionInfo() string {
	return fmt.Sprintf(`%s - %s
Version: %s
Build Date: %s
Git Commit: %s
Platform: Cross-platform (Linux, Android, Windows, macOS)
Language: Go %s`, 
		ProjectName, ProjectDescription, Version, BuildDate, GitCommit, "1.21+")
}
