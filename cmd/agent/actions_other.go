//go:build !linux

package main

import (
	"errors"
	"github.com/Wearden/agent-linux/internal/checks"
	"github.com/Wearden/proto/wire"
	"time"
)

func actionStateTrusted(string) error { return nil }

func restoreRule(*ruleBackup, checks.Rule) error {
	return errors.New("native task recovery requires Linux")
}
func executeRule(string, wire.Task, checks.Rule, time.Time) (wire.ChangeResult, error) {
	return wire.ChangeResult{}, errors.New("native task execution requires Linux")
}
