package main

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"syscall"
)

// Unit masking is the same symlink-to-/dev/null state the native service check
// observes. It does not stop a running unit and does not talk to systemd.
var maskUnitName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}\.(service|socket)$`)

func maskUnits(target string) ([]string, error) {
	units := strings.Split(target, ",")
	if len(units) == 0 || len(units) > 4 {
		return nil, errors.New("unexpected unit list size")
	}
	for _, unit := range units {
		if !maskUnitName.MatchString(unit) {
			return nil, errors.New("unit name is outside the reviewed fixed catalog syntax")
		}
	}
	return units, nil
}

func maskPath(unit string) string { return "etc/systemd/system/" + unit }

// maskState: 0 absent, 1 already a /dev/null mask, error for any other entry.
func maskState(unit string) (int, error) {
	if _, err := secureMutationPath("etc/systemd/system", false); err != nil {
		return 0, err
	}
	info, err := os.Lstat("/" + maskPath(unit))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, errors.New("cannot inspect unit override")
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return 0, errors.New("a real unit override exists and requires manual review")
	}
	to, err := os.Readlink("/" + maskPath(unit))
	if err != nil || to != "/dev/null" {
		return 0, errors.New("unit override is an alias or link requiring manual review")
	}
	return 1, nil
}

// snapshotMask records only the units this task will create; already-masked
// units are never owned by the task and are never removed on recovery.
func snapshotMask(p mutationPlan) (ruleBackup, error) {
	backup := ruleBackup{Kind: "mask", Path: p.Path, Exists: true}
	units, err := maskUnits(p.Payload)
	if err != nil {
		return backup, err
	}
	var created []string
	for _, unit := range units {
		state, err := maskState(unit)
		if err != nil {
			return backup, err
		}
		if state == 0 {
			created = append(created, unit)
		}
	}
	backup.Data = []byte(strings.Join(created, ","))
	// Read-only systemd query: units running now are stopped on apply and
	// started again on recovery. An unreachable manager refuses the whole task.
	manager, err := connectSystemd()
	if err != nil {
		return backup, err
	}
	defer manager.close()
	var running []string
	for _, unit := range units {
		state, err := manager.activeState(unit)
		if err != nil {
			return backup, err
		}
		if state != "inactive" && state != "failed" {
			running = append(running, unit)
		}
	}
	backup.Extra = []byte(strings.Join(running, ","))
	return backup, nil
}

// splitUnits validates a comma list that was journaled by this task.
func splitUnits(list []byte) ([]string, error) {
	if len(list) == 0 {
		return nil, nil
	}
	return maskUnits(string(list))
}

func applyMask(backup *ruleBackup) error {
	units, err := splitUnits(backup.Data)
	if err != nil {
		return err
	}
	running, err := splitUnits(backup.Extra)
	if err != nil {
		return err
	}
	for _, unit := range units {
		if err := syscall.Symlink("/dev/null", "/"+maskPath(unit)); err != nil {
			return errors.New("cannot create unit mask")
		}
	}
	manager, err := connectSystemd()
	if err != nil {
		return err
	}
	defer manager.close()
	if err := manager.reload(); err != nil {
		return err
	}
	for _, unit := range running {
		if err := manager.stop(unit); err != nil {
			return err
		}
	}
	return nil
}

func restoreMask(backup *ruleBackup) error {
	if !backup.Exists || backup.Companion != nil || backup.ParentCreated {
		return errors.New("invalid mask backup shape")
	}
	units, err := splitUnits(backup.Data)
	if err != nil {
		return err
	}
	running, err := splitUnits(backup.Extra)
	if err != nil {
		return err
	}
	for _, unit := range units {
		state, err := maskState(unit)
		if err != nil {
			return err
		}
		if state == 1 {
			if err := os.Remove("/" + maskPath(unit)); err != nil {
				return errors.New("cannot remove task-created unit mask")
			}
		}
	}
	if len(units) == 0 && len(running) == 0 {
		return nil
	}
	manager, err := connectSystemd()
	if err != nil {
		return err
	}
	defer manager.close()
	if err := manager.reload(); err != nil {
		return err
	}
	for _, unit := range running {
		if err := manager.start(unit); err != nil {
			return err
		}
	}
	return nil
}

// auditd enablement is the persistent multi-user.target.wants symlink that the
// native check observes. The unit is never started: no runtime claim is made.
const (
	auditdLink = "etc/systemd/system/multi-user.target.wants/auditd.service"
	auditdUnit = "usr/lib/systemd/system/auditd.service"
)

func auditdLinkState() (bool, error) {
	if _, err := secureMutationPath("etc/systemd/system/multi-user.target.wants", false); err != nil {
		return false, errors.New("multi-user.target.wants is missing or not root-controlled")
	}
	info, err := os.Lstat("/" + auditdLink)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false, errors.New("an unreviewed auditd enablement entry exists")
	}
	if to, err := os.Readlink("/" + auditdLink); err != nil || to != "/"+auditdUnit {
		return false, errors.New("auditd enablement link points elsewhere; manual review required")
	}
	return true, nil
}

func snapshotEnable(p mutationPlan) (ruleBackup, error) {
	backup := ruleBackup{Kind: "enable", Path: p.Path, Exists: true}
	info, err := os.Lstat("/" + auditdUnit)
	if err != nil || !info.Mode().IsRegular() {
		return backup, errors.New("auditd unit is not a regular file in /usr/lib/systemd/system; install it first")
	}
	if _, err := os.Lstat("/etc/systemd/system/auditd.service"); !errors.Is(err, os.ErrNotExist) {
		return backup, errors.New("an auditd unit override exists and requires manual review")
	}
	exists, err := auditdLinkState()
	if err != nil {
		return backup, err
	}
	if !exists {
		backup.Data = []byte("created")
	}
	return backup, nil
}

func reloadSystemd() error {
	manager, err := connectSystemd()
	if err != nil {
		return err
	}
	defer manager.close()
	return manager.reload()
}

func applyEnable(backup *ruleBackup) error {
	if string(backup.Data) != "created" {
		return nil
	}
	if err := syscall.Symlink("/"+auditdUnit, "/"+auditdLink); err != nil {
		return errors.New("cannot create auditd enablement link")
	}
	return reloadSystemd()
}

// Only a link this task created is removed.
func restoreEnable(backup *ruleBackup) error {
	if string(backup.Data) != "created" {
		return nil
	}
	exists, err := auditdLinkState()
	if err != nil {
		return err
	}
	if exists {
		if err := os.Remove("/" + auditdLink); err != nil {
			return errors.New("cannot remove task-created auditd enablement link")
		}
	}
	return reloadSystemd()
}
