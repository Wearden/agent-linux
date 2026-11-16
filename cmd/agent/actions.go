package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Wearden/agent-linux/internal/checks"
	"github.com/Wearden/agent-linux/internal/config"
	"github.com/Wearden/agent-linux/internal/report"
	"github.com/Wearden/proto/wire"
)

type taskJournal struct {
	RecoveryError string           `json:"recovery_error,omitempty"`
	Task          wire.Task        `json:"task"`
	Fingerprint   string           `json:"fingerprint"`
	Result        *wire.TaskResult `json:"result"`
	Authorized    bool             `json:"authorized"`
	Acknowledged  bool             `json:"acknowledged"`
}

type ruleBackup struct {
	TaskID        string      `json:"task_id"`
	RunID         string      `json:"run_id"`
	RuleID        string      `json:"rule_id"`
	Kind          string      `json:"kind"`
	Path          string      `json:"path"`
	Exists        bool        `json:"exists"`
	Data          []byte      `json:"data,omitempty"`
	Mode          uint32      `json:"mode"`
	UID           uint32      `json:"uid"`
	GID           uint32      `json:"gid"`
	Prepared      bool        `json:"prepared"`
	Restored      bool        `json:"restored"`
	Companion     *ruleBackup `json:"companion,omitempty"`
	ParentCreated bool        `json:"parent_created,omitempty"`
	Extra         []byte      `json:"extra,omitempty"`
}

func taskCapacity(dir string, reserve ...int64) error {
	count := 0
	var size int64
	if len(reserve) > 0 {
		size = reserve[0]
	}
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("task state contains a symlink")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("task state must remain private")
		}
		count++
		size += info.Size()
		if count > 10000 || size > 128*1024*1024 {
			return errors.New("task/backup capacity exceeded; retained records need operator archival")
		}
		return nil
	})
}

func taskFingerprint(task wire.Task) string {
	data, _ := json.Marshal(task)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func taskRejection(task wire.Task) string {
	if task.Version != wire.Version || (task.Action != "apply" && task.Action != "rollback") {
		return "unsupported task version or action"
	}
	if task.Action == "apply" && !task.Confirmed {
		return "apply requires explicit confirmation"
	}
	if task.ExpiresAt.IsZero() || !task.ExpiresAt.After(time.Now()) || task.ExpiresAt.After(time.Now().Add(24*time.Hour)) {
		return "task expiry is outside the accepted window"
	}
	if task.SafetyWindowSeconds < 30 || task.SafetyWindowSeconds > 600 {
		return "safety window must be 30..600 seconds"
	}
	return ""
}

func observed(rule checks.Rule) wire.Finding {
	return checks.Run(os.DirFS("/"), []checks.Rule{rule})[0]
}

func backupFile(base, runID, ruleID string) string {
	return filepath.Join(base, "backups", runID, ruleID+".json")
}

func loadBackup(base string, task wire.Task, rule checks.Rule) (ruleBackup, error) {
	var backup ruleBackup
	data, err := readPrivate(backupFile(base, task.RunID, rule.ID), 2*1024*1024)
	if err != nil {
		return backup, err
	}
	if err := decodeJSON(data, &backup); err != nil {
		return backup, err
	}
	if backup.RunID != task.RunID || backup.RuleID != rule.ID {
		return backup, errors.New("backup identity mismatch")
	}
	return backup, nil
}

func failedChange(id, message string) wire.ChangeResult {
	return wire.ChangeResult{RuleID: id, Status: "failed", BeforeStatus: wire.Error, AfterStatus: wire.Error, Message: message}
}

func finishInterrupted(base, agentID string, journal *taskJournal) error {
	result := wire.TaskResult{Version: wire.Version, TaskID: journal.Task.ID, AgentID: agentID, Status: "failed", Changes: []wire.ChangeResult{}}
	for _, id := range journal.Task.RuleIDs {
		change := failedChange(id, "task interrupted before a durable result; no action will be replayed")
		if rule, ok := config.NativeRule(id); ok && journal.Authorized {
			backup, err := loadBackup(base, journal.Task, rule)
			if err == nil && backup.Prepared && (journal.Task.Action == "rollback" || backup.TaskID == journal.Task.ID) {
				if err := restoreRule(&backup, rule); err != nil {
					return fmt.Errorf("interrupted task rollback failed for %s: %w", id, err)
				}
				backup.Restored = true
				if err := atomicJSON(backupFile(base, journal.Task.RunID, id), backup); err != nil {
					return err
				}
				change.BackupID = journal.Task.RunID + "/" + id
				change.Message = "interrupted task recovered from its durable local backup; apply was not replayed"
				if journal.Task.Action == "rollback" {
					change.Status = "reverted"
				}
				finding := observed(rule)
				change.AfterStatus, change.AfterValue = finding.Status, finding.Evidence
			} else if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		result.Changes = append(result.Changes, change)
	}
	journal.Result = &result
	return nil
}

func sendTaskResult(ctx context.Context, client *report.Client, result wire.TaskResult) error {
	data, err := client.Request(ctx, http.MethodPost, "tasks/"+result.TaskID+"/results", result, http.StatusOK, 65536)
	if err != nil {
		return err
	}
	var receipt wire.TaskReceipt
	if err := decodeJSON(data, &receipt); err != nil {
		return err
	}
	if !receipt.Accepted || receipt.TaskID != result.TaskID || receipt.Revision != result.Revision {
		return errors.New("core did not acknowledge this task result")
	}
	return nil
}

func recoverLocalTasks(base, agentID string) ([]taskJournal, error) {
	entries, err := os.ReadDir(filepath.Join(base, "results"))
	if err != nil {
		return nil, err
	}
	if len(entries) > 10000 {
		return nil, errors.New("task journal limit reached; operator archival required")
	}
	journals := []taskJournal{}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".write-") {
			continue
		}
		if filepath.Ext(name) != ".json" {
			return nil, errors.New("incomplete task journal retained; operator recovery required")
		}
		id := strings.TrimSuffix(name, ".json")
		journal, err := recoverJournal(base, agentID, id)
		if err != nil {
			return nil, err
		}
		journals = append(journals, journal)
	}
	return journals, nil
}

func recoverAndFlushTasks(ctx context.Context, base, agentID string, client *report.Client) error {
	journals, err := recoverLocalTasks(base, agentID)
	if err != nil {
		return err
	}
	for _, journal := range journals {
		if err := flushTaskJournal(ctx, base, agentID, journal.Task.ID, client); err != nil {
			return err
		}
	}
	for _, journal := range journals {
		if journal.RecoveryError != "" {
			return errors.New("task recovery needs local operator intervention; no new scans or mutations accepted")
		}
	}
	return nil
}

func prepareTaskState(dir string) (string, error) {
	base := filepath.Join(dir, "tasks")
	for _, name := range []string{base, filepath.Join(base, "results"), filepath.Join(base, "backups"), filepath.Join(base, "watchdogs")} {
		if err := privateDir(name); err != nil {
			return base, err
		}
	}
	return base, actionStateTrusted(base)
}

func processTask(ctx context.Context, dir, agentID string, client *report.Client, allowRemediation bool, benchmark string) error {
	base, err := prepareTaskState(dir)
	if err != nil {
		return err
	}
	if err := recoverAndFlushTasks(ctx, base, agentID, client); err != nil {
		return err
	}
	if err := checks.RequireUbuntuBenchmark(os.DirFS("/"), benchmark); err != nil {
		return err
	}
	if err := taskCapacity(base); err != nil {
		return err
	}
	data, err := client.Request(ctx, http.MethodGet, "tasks", nil, http.StatusOK, 65536)
	if err != nil {
		return err
	}
	var envelope wire.TaskEnvelope
	if err := decodeJSON(data, &envelope); err != nil {
		return err
	}
	if envelope.Task == nil {
		return nil
	}
	task := *envelope.Task
	if !safeIdentity.MatchString(task.ID) || !safeIdentity.MatchString(task.RunID) || len(task.RuleIDs) < 1 || len(task.RuleIDs) > 100 {
		return errors.New("invalid task identity or rule count")
	}
	seen := map[string]bool{}
	for _, id := range task.RuleIDs {
		if !safeIdentity.MatchString(id) || seen[id] {
			return errors.New("invalid or duplicate task rule identity")
		}
		seen[id] = true
	}
	unlockTask, err := lockActionTask(base, task.ID)
	if err != nil {
		return err
	}
	defer func() { unlockTask() }()
	journalPath := filepath.Join(base, "results", task.ID+".json")
	if data, err := readPrivate(journalPath, 2*1024*1024); err == nil {
		var journal taskJournal
		if err := decodeJSON(data, &journal); err != nil {
			return err
		}
		if journal.Fingerprint != taskFingerprint(task) || journal.Result == nil {
			return errors.New("task ID was reused or has incomplete recovery")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(filepath.Join(base, "results"))
	if err != nil {
		return err
	}
	if len(entries) >= 512 {
		return errors.New("task journal capacity reached; no new mutations accepted")
	}
	if err := taskCapacity(base, 1024*1024); err != nil {
		return err
	}
	rejection := taskRejection(task)
	if !allowRemediation {
		rejection = "daemon is scan-only; restart with -allow-remediation to accept native mutation tasks"
	}
	journal := taskJournal{Task: task, Fingerprint: taskFingerprint(task), Authorized: rejection == ""}
	if err := atomicJSON(journalPath, journal); err != nil {
		return err
	}
	result := wire.TaskResult{Version: wire.Version, TaskID: task.ID, AgentID: agentID, Status: "completed", Changes: []wire.ChangeResult{}}
	deadline := time.Now().Add(time.Duration(task.SafetyWindowSeconds) * time.Second)
	if task.ExpiresAt.Before(deadline) {
		deadline = time.Now().Add(time.Until(task.ExpiresAt))
	}
	if journal.Authorized && task.Action == "apply" {
		if err := armWatchdog(base, agentID, journal, deadline); err != nil {
			rejection = err.Error()
			journal.Authorized = false
			if e := atomicJSON(journalPath, journal); e != nil {
				return e
			}
		}
	}
	for _, id := range task.RuleIDs {
		change := failedChange(id, "rule is not in the local native catalog")
		if rejection != "" {
			change.Message = rejection
		} else if ctx.Err() != nil || time.Now().After(deadline) {
			change.Message = "task cancelled or safety window elapsed before this change"
		} else if rule, ok := config.NativeRule(id); ok {
			if err := taskCapacity(base); err != nil {
				return err
			}
			change, err = executeRule(base, task, rule, deadline)
			if err != nil {
				return err
			} // A failed recovery is fatal: keep the incomplete journal for restart recovery.
		}
		if change.Status == "failed" {
			result.Status = "failed"
		}
		result.Changes = append(result.Changes, change)
	}
	journal.Result = &result
	for _, c := range result.Changes {
		level := "info"
		if c.Status == "failed" {
			level = "warn"
		}
		agentLog(level, "task %s %s %s: %s", task.ID, task.Action, c.RuleID, c.Status)
	}
	agentLog("info", "task %s %s finished with status %s (%d changes)", task.ID, task.Action, result.Status, len(result.Changes))
	if err := atomicJSON(journalPath, journal); err != nil {
		return err
	}
	// Release the mutation lock before the receipt phase; the flush helper rereads
	// the durable result so a watchdog correction cannot be overwritten by stale data.
	unlockTask()
	unlockTask = func() {}
	return flushTaskJournal(ctx, base, agentID, task.ID, client)
}
