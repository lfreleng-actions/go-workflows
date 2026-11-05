// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation

// Command go-module is the build-test fixture for the resolved
// dependency-change lane; it only greets.
package main

import "fmt"

// Greeting returns the line main prints.
func Greeting() string {
	return "go-workflows fixture"
}

func main() {
	fmt.Println(Greeting())
}
