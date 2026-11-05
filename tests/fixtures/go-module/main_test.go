// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation

package main

import "testing"

func TestGreeting(t *testing.T) {
	if got := Greeting(); got != "go-workflows fixture" {
		t.Errorf("Greeting() = %q", got)
	}
}
