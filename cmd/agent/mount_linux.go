package main

import (
	"errors"
	"os"
	"strings"
	"syscall"
)

// Runtime-only per-mount flag hardening for fixed targets. The mount point must
// exist exactly in this namespace; nothing is mounted, unmounted or persisted.
const mountHardeningOptions = "nodev,nosuid,noexec"

func mountFlagBits() map[string]uintptr {
	return map[string]uintptr{
		"rw": 0, "ro": syscall.MS_RDONLY, "nosuid": syscall.MS_NOSUID, "nodev": syscall.MS_NODEV,
		"noexec": syscall.MS_NOEXEC, "noatime": syscall.MS_NOATIME, "nodiratime": syscall.MS_NODIRATIME,
		"relatime": syscall.MS_RELATIME,
	}
}

// currentMountOptions returns the per-mount option string of the single mount
// whose mount point equals target exactly.
func currentMountOptions(target string) (string, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil || len(data) > 8*1024*1024 {
		return "", errors.New("cannot read bounded mountinfo")
	}
	found := ""
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			return "", errors.New("malformed mountinfo")
		}
		fields := strings.Fields(parts[0])
		if len(fields) < 6 {
			return "", errors.New("malformed mountinfo")
		}
		if fields[4] == target {
			found = fields[5]
			count++
		}
	}
	if count != 1 {
		return "", errors.New("target is not exactly one dedicated mount in this namespace; no remount attempted")
	}
	return found, nil
}

func mountFlags(options string) (uintptr, error) {
	bits := mountFlagBits()
	var flags uintptr
	for _, option := range strings.Split(options, ",") {
		bit, ok := bits[option]
		if !ok {
			return 0, errors.New("mount uses options outside the reviewed remount subset")
		}
		flags |= bit
	}
	if !strings.Contains(","+options+",", ",relatime,") && !strings.Contains(","+options+",", ",noatime,") {
		flags |= syscall.MS_STRICTATIME
	}
	return flags, nil
}

func remountOptions(target, options string) error {
	flags, err := mountFlags(options)
	if err != nil {
		return err
	}
	if err := syscall.Mount("", target, "", syscall.MS_REMOUNT|syscall.MS_BIND|flags, ""); err != nil {
		return errors.New("per-mount flag remount failed")
	}
	return nil
}

func hardenedMountOptions(original string) string {
	have := map[string]bool{}
	for _, o := range strings.Split(original, ",") {
		have[o] = true
	}
	out := original
	for _, o := range strings.Split(mountHardeningOptions, ",") {
		if !have[o] {
			out += "," + o
		}
	}
	return out
}
