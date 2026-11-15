package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/Wearden/agent-linux/internal/report"
	"github.com/Wearden/proto/wire"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type watchdogReady struct {
	TaskID      string `json:"task_id"`
	PID         int    `json:"pid"`
	Fingerprint string `json:"fingerprint"`
}

type watchdogLease struct {
	BootID       string    `json:"boot_id"`
	BootDeadline float64   `json:"boot_deadline"`
	TaskID       string    `json:"task_id"`
	AgentID      string    `json:"agent_id"`
	Deadline     time.Time `json:"deadline"`
}

func leasePath(base, id string) string { return filepath.Join(base, "watchdogs", id+".json") }
func readJournal(base, id string) (taskJournal, error) {
	var journal taskJournal
	data, err := readPrivate(filepath.Join(base, "results", id+".json"), 2*1024*1024)
	if err != nil {
		return journal, err
	}
	if err = decodeJSON(data, &journal); err != nil {
		return journal, err
	}
	if journal.Task.ID != id || journal.Fingerprint != taskFingerprint(journal.Task) || !safeIdentity.MatchString(journal.Task.RunID) {
		return journal, errors.New("watchdog journal identity mismatch")
	}
	return journal, nil
}
func watchdogClock() (string, float64, error) {
	read := func(name string) (string, error) {
		f, err := os.Open(name)
		if err != nil {
			return "", err
		}
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, 256))
		return strings.TrimSpace(string(data)), err
	}
	id, err := read("/proc/sys/kernel/random/boot_id")
	if err != nil || len(id) != 36 || !safeIdentity.MatchString(id) {
		return "", 0, errors.New("kernel boot identity is unavailable")
	}
	uptime, err := read("/proc/uptime")
	fields := strings.Fields(uptime)
	if err != nil || len(fields) != 2 {
		return "", 0, errors.New("kernel elapsed time is unavailable")
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return "", 0, errors.New("invalid kernel elapsed time")
	}
	return id, value, nil
}
func watchdogDeadline(base, id string) (time.Time, error) {
	var lease watchdogLease
	data, err := readPrivate(leasePath(base, id), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	if err = decodeJSON(data, &lease); err != nil {
		return time.Time{}, err
	}
	if lease.TaskID != id || !safeIdentity.MatchString(lease.AgentID) || lease.Deadline.IsZero() || lease.BootID == "" || math.IsNaN(lease.BootDeadline) || math.IsInf(lease.BootDeadline, 0) {
		return time.Time{}, errors.New("invalid watchdog lease")
	}
	boot, elapsed, err := watchdogClock()
	if err != nil {
		return time.Time{}, err
	}
	if boot != lease.BootID {
		return time.Now().Add(-time.Second), nil
	}
	remaining := lease.BootDeadline - elapsed
	if remaining <= 0 {
		return time.Now().Add(-time.Second), nil
	}
	if remaining > 600 {
		return time.Time{}, errors.New("watchdog lease exceeds maximum safety window")
	}
	return time.Now().Add(time.Duration(remaining * float64(time.Second))), nil
}

func compensateExpired(base, agentID string, journal *taskJournal) error {
	if journal.Result != nil && journal.Result.Revision == 1 {
		return nil
	}
	if err := finishInterrupted(base, agentID, journal); err != nil {
		journal.RecoveryError = err.Error()
		failed := wire.TaskResult{Version: wire.Version, TaskID: journal.Task.ID, AgentID: agentID, Status: "failed"}
		for _, id := range journal.Task.RuleIDs {
			failed.Changes = append(failed.Changes, failedChange(id, "Watchdog recovery could not be fully verified; local operator intervention is required"))
		}
		journal.Result = &failed
	}
	journal.Result.Revision = 1
	if journal.RecoveryError == "" {
		for i := range journal.Result.Changes {
			journal.Result.Changes[i].Message = "Connectivity watchdog deadline elapsed; original local backup restored"
		}
	}
	journal.Acknowledged = false
	return atomicJSON(filepath.Join(base, "results", journal.Task.ID+".json"), journal)
}

func recoverJournal(base, agentID, id string) (taskJournal, error) {
	unlock, err := lockActionTask(base, id)
	if err != nil {
		return taskJournal{}, err
	}
	defer unlock()
	journal, err := readJournal(base, id)
	if err != nil {
		return journal, err
	}
	if journal.Result == nil {
		if err = finishInterrupted(base, agentID, &journal); err == nil {
			err = atomicJSON(filepath.Join(base, "results", id+".json"), journal)
		}
		return journal, err
	}
	var deadline time.Time
	if journal.Authorized && journal.Result.Revision == 0 {
		deadline, err = watchdogDeadline(base, id)
	}
	if err != nil {
		return journal, err
	}
	if journal.Authorized && !journal.Acknowledged && !deadline.IsZero() && !time.Now().Before(deadline) && journal.Task.Action == "apply" {
		err = compensateExpired(base, agentID, &journal)
	}
	if journal.Result.AgentID != agentID {
		return journal, errors.New("task result belongs to another agent")
	}
	return journal, err
}

// The task lock covers both the HTTP acknowledgement and its durable local commit.
// A receipt after the deadline is not committed; revision1 corrects any accepted
// revision0 when the independent helper has to restore the original state.
func flushTaskJournal(ctx context.Context, base, agentID, id string, client *report.Client) error {
	unlock, err := lockActionTask(base, id)
	if err != nil {
		return err
	}
	defer unlock()
	journal, err := readJournal(base, id)
	if err != nil {
		return err
	}
	if journal.Result == nil {
		return errors.New("incomplete task must recover before sending")
	}
	if journal.Acknowledged {
		return nil
	}
	var deadline time.Time
	if journal.Authorized && journal.Result.Revision == 0 {
		deadline, err = watchdogDeadline(base, id)
	}
	if err != nil {
		return err
	}
	if journal.Authorized && !deadline.IsZero() && !time.Now().Before(deadline) && journal.Task.Action == "apply" {
		if err = compensateExpired(base, agentID, &journal); err != nil {
			return err
		}
	}
	if err = sendTaskResult(ctx, client, *journal.Result); err != nil {
		return err
	}
	if journal.Authorized && journal.Result.Revision == 0 {
		deadline, err = watchdogDeadline(base, id)
	} else {
		deadline = time.Time{}
	}
	if err != nil {
		return err
	}
	if journal.Authorized && journal.Result.Revision == 0 && !deadline.IsZero() && !time.Now().Before(deadline) {
		return errors.New("receipt arrived after watchdog deadline; recovery will be recorded separately")
	}
	journal.Acknowledged = true
	return atomicJSON(filepath.Join(base, "results", id+".json"), journal)
}
func runWatchdog(base, id string) error {
	if !watchdogRootAllowed() {
		return errors.New("watchdog recovery requires root on Linux")
	}
	if !safeIdentity.MatchString(id) || !filepath.IsAbs(base) {
		return errors.New("invalid watchdog scope")
	}
	if err := actionStateTrusted(base); err != nil {
		return err
	}
	var lease watchdogLease
	data, err := readPrivate(leasePath(base, id), 4096)
	if err != nil {
		return err
	}
	if err = decodeJSON(data, &lease); err != nil {
		return err
	}
	if lease.TaskID != id || !safeIdentity.MatchString(lease.AgentID) {
		return errors.New("invalid watchdog identity")
	}
	if _, err := watchdogDeadline(base, id); err != nil {
		return err
	}
	journal, err := readJournal(base, id)
	if err != nil || !journal.Authorized || journal.Task.Action != "apply" {
		return errors.New("watchdog has no authorized apply journal")
	}
	if err = atomicJSON(filepath.Join(base, "watchdogs", id+".ready.json"), watchdogReady{TaskID: id, PID: os.Getpid(), Fingerprint: journal.Fingerprint}); err != nil {
		return err
	}
	for {
		unlock, err := lockActionTask(base, id)
		if err != nil {
			return err
		}
		journal, err := readJournal(base, id)
		if err != nil {
			unlock()
			return err
		}
		if journal.Acknowledged || journal.Result != nil && journal.Result.Revision == 1 {
			unlock()
			return nil
		}
		deadline, e := watchdogDeadline(base, id)
		if e != nil {
			err = compensateExpired(base, lease.AgentID, &journal)
			unlock()
			return err
		}
		if !time.Now().Before(deadline) {
			if !journal.Authorized || journal.Task.Action != "apply" {
				unlock()
				return nil
			}
			err = compensateExpired(base, lease.AgentID, &journal)
			unlock()
			if err != nil {
				return fmt.Errorf("watchdog restore requires operator recovery: %w", err)
			}
			return nil
		}
		unlock()
		time.Sleep(250 * time.Millisecond)
	}
}

// Manual recovery is local-only, requires exclusive daemon state ownership and
// restores only the immutable task's approved backups. It never marks a core
// receipt acknowledged or rewrites an already-uploaded result revision.
func recoverManualTask(dir, id string) error {
	if !watchdogRootAllowed() || !safeIdentity.MatchString(id) {
		return errors.New("manual task recovery requires root and a valid task ID")
	}
	unlockState, err := lockState(dir)
	if err != nil {
		return err
	}
	defer unlockState()
	base, err := prepareTaskState(dir)
	if err != nil {
		return err
	}
	unlock, err := lockActionTask(base, id)
	if err != nil {
		return err
	}
	defer unlock()
	journal, err := readJournal(base, id)
	if err != nil {
		return err
	}
	if !journal.Authorized || journal.Task.Action != "apply" {
		return errors.New("task has no authorized apply snapshots")
	}
	agentID := ""
	if journal.Result != nil {
		agentID = journal.Result.AgentID
	}
	if agentID == "" {
		var lease watchdogLease
		raw, e := readPrivate(leasePath(base, id), 4096)
		if e != nil {
			return errors.New("task agent identity is unavailable")
		}
		if decodeJSON(raw, &lease) != nil {
			return errors.New("invalid private recovery lease")
		}
		agentID = lease.AgentID
	}
	if !safeIdentity.MatchString(agentID) {
		return errors.New("invalid stored agent identity")
	}
	previous, ack := journal.Result, journal.Acknowledged
	if err = finishInterrupted(base, agentID, &journal); err != nil {
		return err
	}
	if previous != nil && previous.Revision == 1 {
		journal.Result = previous
		journal.Acknowledged = ack
	} else {
		journal.Result.Revision = 1
		journal.Acknowledged = false
		for i := range journal.Result.Changes {
			journal.Result.Changes[i].Message = "Local operator restored original state from the task backup"
		}
	}
	journal.RecoveryError = ""
	return atomicJSON(filepath.Join(base, "results", id+".json"), journal)
}
