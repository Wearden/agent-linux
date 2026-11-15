package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Wearden/agent-linux/internal/checks"
	"github.com/Wearden/agent-linux/internal/config"
	"github.com/Wearden/proto/wire"
)

type mutationPlan struct {
	Kind, Path, Payload, Persistent string
	CompanionPath, CompanionPayload string
	Mode                            fs.FileMode
	Owner                           bool
}

func actionStateTrusted(base string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	abs, err := filepath.Abs(base)
	if err != nil {
		return err
	}
	_, err = secureMutationPath(strings.TrimPrefix(filepath.ToSlash(abs), "/")+"/.ownership-check", true)
	if err != nil {
		return errors.New("root task state and all its ancestors must be root-controlled without symlinks or group/world write access")
	}
	return nil
}

func planMutation(rule checks.Rule) (mutationPlan, error) {
	var p mutationPlan
	switch rule.Kind {
	case "sshd_config":
		approved, known := config.NativeRule(rule.ID)
		if !known || approved != rule {
			return p, errors.New("SSH mutation rule differs from the embedded catalog")
		}
		value, known := checks.SSHBaseline(rule.Target)
		if !known {
			return p, errors.New("SSH option has no compiled mutation baseline")
		}
		p = mutationPlan{Kind: "file", Path: "etc/ssh/sshd_config.d/00-wearden-" + rule.ID + ".conf", Payload: rule.Target + " " + value + "\n", Mode: 0600, Owner: true}
		if rule.ID == "LNX-SSH-015" {
			p.CompanionPath = "etc/issue.net"
			p.CompanionPayload = "Authorised use only. All activity is monitored and logged.\n"
		}
	case "kernel_module":
		p = mutationPlan{Kind: "file", Path: "etc/modprobe.d/99-wearden-" + rule.ID + ".conf", Payload: "blacklist " + rule.Target + "\ninstall " + rule.Target + " /bin/false\n", Mode: 0644, Owner: true}
	case "sysctl":
		if rule.ID == "LNX-NET-001" {
			return p, errors.New("ip_forward can reset other IPv4 settings; single-parameter backup cannot safely restore that change")
		}
		value := "0"
		switch rule.ID {
		case "LNX-NET-002", "LNX-NET-003", "LNX-NET-004", "LNX-NET-005", "LNX-NET-006", "LNX-NET-007", "LNX-NET-008":
		case "LNX-NET-009", "LNX-NET-010", "LNX-NET-011":
			value = "1"
		case "LNX-NET-012":
			value = "2"
		default:
			return p, errors.New("sysctl control is outside the reviewed write allowlist")
		}
		p = mutationPlan{Kind: "sysctl", Path: "proc/sys/" + strings.ReplaceAll(rule.Target, ".", "/"), Payload: value + "\n", Persistent: "etc/sysctl.d/99-wearden-" + rule.ID + ".conf", Mode: 0644, Owner: true}
	case "journald_config":
		value := "persistent"
		if rule.Target == "Compress" {
			value = "yes"
		}
		p = mutationPlan{Kind: "file", Path: "etc/systemd/journald.conf.d/99-wearden-" + rule.ID + ".conf", Payload: "[Journal]\n" + rule.Target + "=" + value + "\n", Mode: 0644, Owner: true}
	case "file_metadata":
		p = mutationPlan{Kind: "metadata", Path: strings.TrimPrefix(rule.Target, "/"), Mode: 0600, Owner: true}
		switch rule.ID {
		case "LNX-USR-001", "LNX-USR-003":
			p.Mode = 0644
		case "LNX-USR-010":
			p.Mode, p.Owner = 0700, false
		case "LNX-USR-011", "LNX-SSH-001":
		case "LNX-USR-012":
			p.Mode = 0440
		case "LNX-LOG-003":
			p.Owner = false
		default:
			return p, errors.New("credential-file metadata changes are read-only in this engine")
		}
	default:
		return p, errors.New("control has no reviewed safe native mutation; no shell, authentication, package or firewall action will execute")
	}
	return p, nil
}

// Parent directories must be controlled by root, preventing an unprivileged
// account from exchanging an ancestor after inspection. Final opens use NOFOLLOW.
func secureMutationPath(name string, allowMissing bool) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, errors.New("invalid local mutation path")
	}
	parts := strings.Split(name, "/")
	current := "/"
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			if allowMissing && i == len(parts)-1 && errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			return nil, errors.New("required local path is unavailable")
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, errors.New("symlinked mutation paths are refused")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, errors.New("native path ownership is unavailable")
		}
		if i < len(parts)-1 && (!info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0) {
			return nil, errors.New("mutation parent is not a root-controlled directory")
		}
		if i == len(parts)-1 {
			return info, nil
		}
	}
	return nil, errors.New("invalid local mutation path")
}

func reviewedMutationDirectory(parent string) bool {
	switch parent {
	case "etc/systemd/journald.conf.d", "etc/modprobe.d", "etc/sysctl.d", "etc/ssh/sshd_config.d":
		return true
	}
	return false
}

func ensureMutationParent(name string) error {
	parent := path.Dir(name)
	if _, err := secureMutationPath(parent, false); err == nil {
		return nil
	}
	if !reviewedMutationDirectory(parent) {
		return errors.New("required mutation directory does not exist")
	}
	if _, err := secureMutationPath(path.Dir(parent), false); err != nil {
		return err
	}
	if err := os.Mkdir("/"+parent, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("cannot create reviewed configuration directory")
	}
	info, err := secureMutationPath(parent, false)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("configuration directory is not root-controlled")
	}
	return nil
}

func snapshotBeforeMutation(name, kind string) (ruleBackup, error) {
	if kind == "file" {
		parent := path.Dir(name)
		info, err := secureMutationPath(parent, true)
		if err != nil {
			return ruleBackup{}, err
		}
		if info == nil {
			if !reviewedMutationDirectory(parent) {
				return ruleBackup{}, errors.New("configuration parent is outside reviewed directory creation policy")
			}
			return ruleBackup{Kind: kind, Path: name, ParentCreated: true}, nil
		}
	}
	return snapshotMutation(name, kind)
}

func snapshotMutation(name, kind string) (ruleBackup, error) {
	backup := ruleBackup{Path: name, Kind: kind}
	info, err := secureMutationPath(name, kind == "file")
	if err != nil {
		return backup, err
	}
	if info == nil {
		return backup, nil
	}
	backup.Exists = true
	backup.Mode = uint32(info.Mode())
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return backup, errors.New("cannot capture native owner metadata")
	}
	backup.UID, backup.GID = stat.Uid, stat.Gid
	if kind == "file" && (stat.Uid != 0 || info.Mode().Perm()&0022 != 0) {
		return backup, errors.New("managed configuration must be root-owned and not group/world writable")
	}
	if info.Mode().IsRegular() && stat.Nlink != 1 {
		return backup, errors.New("hard-linked targets require manual review")
	}
	if n, err := syscall.Listxattr("/"+name, nil); err == nil && n > 0 {
		return backup, errors.New("targets with extended attributes or ACLs need a richer backup format and are refused")
	} else if err != nil && err != syscall.ENOTSUP {
		return backup, errors.New("cannot inspect target extended attributes")
	}
	if kind == "metadata" {
		if !info.Mode().IsRegular() && !info.IsDir() {
			return backup, errors.New("metadata target is not a regular file or directory")
		}
		return backup, nil
	}
	if !info.Mode().IsRegular() {
		return backup, errors.New("configuration target is not a regular file")
	}
	f, err := os.OpenFile("/"+name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return backup, errors.New("cannot open local backup source")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return backup, errors.New("backup source is unreadable or exceeds 1 MiB")
	}
	if kind == "sysctl" {
		if _, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32); err != nil {
			return backup, errors.New("runtime sysctl backup is not numeric")
		}
	}
	backup.Data = data
	return backup, nil
}

func writeManaged(name string, data []byte, mode fs.FileMode, uid, gid uint32) error {
	if err := ensureMutationParent(name); err != nil {
		return err
	}
	if _, err := secureMutationPath(name, true); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir("/"+name), ".wearden-write-*")
	if err != nil {
		return errors.New("cannot create managed configuration temporary file")
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chown(int(uid), int(gid)); err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("cannot persist managed configuration")
	}
	if err := os.Rename(tmp, "/"+name); err != nil {
		return errors.New("cannot replace managed configuration")
	}
	return syncDir(filepath.Dir("/" + name))
}

func writeSysctl(name string, data []byte) error {
	if _, err := secureMutationPath(name, false); err != nil {
		return err
	}
	f, err := os.OpenFile("/"+name, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("cannot open approved runtime sysctl")
	}
	n, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil || n != len(data) {
		return errors.New("runtime sysctl write failed")
	}
	return nil
}

func writeMetadata(name string, mode fs.FileMode, uid, gid uint32) error {
	if _, err := secureMutationPath(name, false); err != nil {
		return err
	}
	f, err := os.OpenFile("/"+name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("cannot open metadata target without following symlinks")
	}
	defer f.Close()
	if err := f.Chown(int(uid), int(gid)); err != nil {
		return errors.New("cannot restore approved ownership")
	}
	if err := f.Chmod(mode); err != nil {
		return errors.New("cannot set approved permissions")
	}
	return f.Sync()
}

func restoreRule(backup *ruleBackup, rule checks.Rule) error {
	if os.Geteuid() != 0 {
		return errors.New("native recovery requires root")
	}
	p, err := planMutation(rule)
	if err != nil {
		return err
	}
	if backup.Kind != p.Kind || backup.Path != p.Path {
		return errors.New("backup path does not match locally approved rule")
	}
	companionPath := p.CompanionPath
	if p.Kind == "sysctl" {
		companionPath = p.Persistent
	}
	if companionPath != "" && backup.Companion == nil {
		return errors.New("required companion backup is absent")
	}
	if backup.Companion != nil {
		if companionPath == "" || backup.Companion.Path != companionPath || backup.Companion.Kind != "file" || backup.Companion.Companion != nil {
			return errors.New("invalid companion configuration backup")
		}
		if err := restoreSnapshot(backup.Companion); err != nil {
			return err
		}
	}
	return restoreSnapshot(backup)
}

func restoreSnapshot(backup *ruleBackup) error {
	if backup.ParentCreated && (backup.Exists || backup.Kind != "file" || !reviewedMutationDirectory(path.Dir(backup.Path))) {
		return errors.New("created-parent backup is outside the reviewed directory policy")
	}
	if !backup.Exists {
		if backup.ParentCreated {
			parent, err := secureMutationPath(path.Dir(backup.Path), true)
			if err != nil {
				return err
			}
			if parent == nil {
				return nil
			}
		}
		info, err := secureMutationPath(backup.Path, true)
		if err != nil {
			return err
		}
		if info == nil {
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("refusing to remove non-regular configuration during rollback")
		}
		if err := os.Remove("/" + backup.Path); err != nil {
			return errors.New("cannot remove task-created configuration")
		}
		return syncDir(filepath.Dir("/" + backup.Path))
	}
	var err error
	switch backup.Kind {
	case "metadata":
		err = writeMetadata(backup.Path, fs.FileMode(backup.Mode), backup.UID, backup.GID)
	case "sysctl":
		err = writeSysctl(backup.Path, backup.Data)
	case "file":
		err = writeManaged(backup.Path, backup.Data, fs.FileMode(backup.Mode), backup.UID, backup.GID)
	default:
		return errors.New("unknown local backup kind")
	}
	if err != nil {
		return err
	}
	current, err := snapshotMutation(backup.Path, backup.Kind)
	if err != nil {
		return err
	}
	if !current.Exists || current.Mode != backup.Mode || current.UID != backup.UID || current.GID != backup.GID {
		return errors.New("restored metadata does not match the durable backup")
	}
	if backup.Kind == "sysctl" {
		if strings.TrimSpace(string(current.Data)) != strings.TrimSpace(string(backup.Data)) {
			return errors.New("restored sysctl does not match its backup")
		}
	} else if !bytes.Equal(current.Data, backup.Data) {
		return errors.New("restored configuration does not match its backup")
	}
	return nil
}

func executeRule(base string, task wire.Task, rule checks.Rule, deadline time.Time) (wire.ChangeResult, error) {
	change := failedChange(rule.ID, "")
	p, err := planMutation(rule)
	if err != nil {
		change.Message = err.Error()
		return change, nil
	}
	if rule.Kind == "sshd_config" {
		change.Message = "SSH native plan is prepared but execution requires banner and daemon validation/reload integration; no mutation attempted"
		return change, nil
	}
	if os.Geteuid() != 0 {
		change.Message = "native remediation requires a root-owned service"
		return change, nil
	}
	before := observed(rule)
	change.BeforeStatus, change.BeforeValue = before.Status, before.Evidence
	if task.Action == "rollback" {
		backup, err := loadBackup(base, task, rule)
		if err != nil {
			change.Message = "durable local backup is unavailable"
			return change, nil
		}
		if err := restoreRule(&backup, rule); err != nil {
			change.Message = "rollback failed: " + err.Error()
			return change, nil
		}
		backup.Restored = true
		if err := atomicJSON(backupFile(base, task.RunID, rule.ID), backup); err != nil {
			return change, err
		}
		after := observed(rule)
		change.Status, change.AfterStatus, change.AfterValue = "reverted", after.Status, after.Evidence
		change.BackupID = task.RunID + "/" + rule.ID
		change.Message = "restored original local state; a reverted control may intentionally be non-compliant"
		return change, nil
	}
	if before.Status == wire.Pass {
		change.Status, change.AfterStatus, change.AfterValue = "skipped", before.Status, before.Evidence
		change.Message = "already satisfies the reviewed native check"
		return change, nil
	}
	if rule.Kind == "kernel_module" && (before.Status != wire.Fail || before.Evidence != "requires both blacklist and install blocking") {
		change.Message = "module is active or its policy is ambiguous; no live unload or override attempted"
		return change, nil
	}
	if before.Status == wire.Error && !(rule.Kind == "journald_config" && before.Evidence == "journal setting is implicit or absent") {
		change.Message = "native precheck cannot safely establish current state"
		return change, nil
	}
	backup, err := snapshotBeforeMutation(p.Path, p.Kind)
	if err != nil {
		change.Message = err.Error()
		return change, nil
	}
	backup.TaskID, backup.RunID, backup.RuleID, backup.Prepared = task.ID, task.RunID, rule.ID, true
	companionPath := p.CompanionPath
	if p.Kind == "sysctl" {
		companionPath = p.Persistent
	}
	if companionPath != "" {
		companion, err := snapshotBeforeMutation(companionPath, "file")
		if err != nil {
			change.Message = err.Error()
			return change, nil
		}
		backup.Companion = &companion
	}
	if err := privateDir(filepath.Join(base, "backups", task.RunID)); err != nil {
		return change, err
	}
	location := backupFile(base, task.RunID, rule.ID)
	if _, err := os.Lstat(location); err == nil {
		change.Message = "this run/rule already has a retained backup; refusing to overwrite it"
		return change, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return change, err
	}
	encoded, err := json.Marshal(backup)
	if err != nil {
		return change, err
	}
	if err := taskCapacity(base, int64(len(encoded))+1024*1024); err != nil {
		change.Message = "local backup capacity would be exceeded; no mutation attempted"
		return change, nil
	}
	if err := atomicJSON(location, backup); err != nil {
		return change, err
	}
	change.BackupID = task.RunID + "/" + rule.ID
	uid, gid := backup.UID, backup.GID
	if p.Owner {
		uid, gid = 0, 0
	}
	switch p.Kind {
	case "metadata":
		err = writeMetadata(p.Path, p.Mode, uid, gid)
	case "file":
		if p.CompanionPath != "" {
			err = writeManaged(p.CompanionPath, []byte(p.CompanionPayload), 0644, 0, 0)
		}
		if err == nil {
			err = writeManaged(p.Path, []byte(p.Payload), p.Mode, uid, gid)
		}
	case "sysctl":
		err = writeManaged(p.Persistent, []byte(rule.Target+" = "+strings.TrimSpace(p.Payload)+"\n"), 0644, 0, 0)
		if err == nil {
			err = writeSysctl(p.Path, []byte(p.Payload))
		}
	}
	if err == nil && p.CompanionPath != "" {
		companion, verifyErr := snapshotMutation(p.CompanionPath, "file")
		if verifyErr != nil || !companion.Exists || companion.Mode != 0644 || companion.UID != 0 || companion.GID != 0 || !bytes.Equal(companion.Data, []byte(p.CompanionPayload)) {
			err = errors.New("managed companion content or metadata did not match the compiled plan")
		}
	}
	after := observed(rule)
	if err != nil || after.Status != wire.Pass || time.Now().After(deadline) {
		if restoreErr := restoreRule(&backup, rule); restoreErr != nil {
			return change, fmt.Errorf("failed apply could not restore %s: %w", rule.ID, restoreErr)
		}
		backup.Restored = true
		if err := atomicJSON(location, backup); err != nil {
			return change, err
		}
		restored := observed(rule)
		change.AfterStatus, change.AfterValue = restored.Status, restored.Evidence
		change.Message = "apply failed or native recheck did not pass; original backup restored"
		return change, nil
	}
	change.Status, change.AfterStatus, change.AfterValue = "applied", after.Status, after.Evidence
	change.Message = "native change applied and rechecked; local backup retained"
	if rule.Kind == "journald_config" {
		change.Message = "journal file policy applied and rechecked; daemon reload state is not attested"
	}
	if rule.Kind == "kernel_module" {
		change.Message = "unloaded-module file policy applied and rechecked; loaded modules are never removed"
	}
	if rule.Kind == "sysctl" {
		change.Message = "runtime sysctl changed and rechecked; persistent drop-in saved, boot-time precedence is not attested"
	}
	return change, nil
}
