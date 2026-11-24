//go:build !windows

// Command nr-sim-block is a Windows test tool; see main_windows.go.
package main

import "fmt"

func main() { fmt.Println("nr-sim-block runs on Windows only") }
