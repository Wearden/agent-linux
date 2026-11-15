package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func lockActionTask(base, id string) (func(), error) {
	if !safeIdentity.MatchString(id) {
		return nil, errors.New("invalid local task lock identity")
	}
	dir := filepath.Join(base, "watchdogs")
	if err := privateDir(dir); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(filepath.Join(dir, id+".lock"), syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "task-lock")
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("unsafe task lock file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || (os.Geteuid() == 0 && stat.Uid != 0) {
		f.Close()
		return nil, errors.New("task lock ownership or link count is unsafe")
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}
func armWatchdog(base, agentID string, journal taskJournal, deadline time.Time) error {
	if os.Geteuid() != 0 {
		return errors.New("independent recovery requires a root-owned agent")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	info, err := secureMutationPath(filepath.ToSlash(executable)[1:], false)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("watchdog executable must be root-controlled and not group/world writable")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return errors.New("watchdog executable is not owned by root")
	}
	boot, elapsed, err := watchdogClock()
	if err != nil {
		return err
	}
	remaining := time.Until(deadline).Seconds()
	if remaining <= 0 || remaining > 600 {
		return errors.New("invalid watchdog execution window")
	}
	if err := atomicJSON(leasePath(base, journal.Task.ID), watchdogLease{TaskID: journal.Task.ID, AgentID: agentID, Deadline: deadline, BootID: boot, BootDeadline: elapsed + remaining}); err != nil {
		return err
	}
	command := exec.Command(executable, "-watchdog-dir", base, "-watchdog-task", journal.Task.ID)
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = command.Start(); err != nil {
		return errors.New("cannot start independent recovery process")
	}
	pid := command.Process.Pid
	go func() {
		if err := command.Wait(); err != nil {
			fmt.Fprintln(os.Stderr, "independent recovery process exited with an error; retained task state requires review")
		}
	}()
	readyDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(readyDeadline) {
		data, e := readPrivate(filepath.Join(base, "watchdogs", journal.Task.ID+".ready.json"), 4096)
		if e == nil {
			var ready watchdogReady
			if decodeJSON(data, &ready) == nil && ready.TaskID == journal.Task.ID && ready.PID == pid && ready.Fingerprint == journal.Fingerprint {
				return nil
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("independent recovery process did not become ready; no mutation authorized")
}

func watchdogRootAllowed() bool { return os.Geteuid() == 0 }
