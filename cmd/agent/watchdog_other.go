//go:build !linux

package main

import (
	"errors"
	"time"
)

func lockActionTask(string, string) (func(), error) { return func() {}, nil }
func armWatchdog(string, string, taskJournal, time.Time) error {
	return errors.New("watchdog requires Linux")
}

func watchdogRootAllowed() bool { return false }
