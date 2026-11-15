package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Wearden/agent-linux/internal/checks"
	"golang.org/x/sys/unix"
)

type sshProcessCandidate struct {
	pidfd *os.File
	pid   int
	start uint64
}

// This pins a process instance only. Listener and original-argument validation
// are still required before any reload; this helper sends no signal.
func pinSSHProcessCandidate(pid int, executable *os.File) (candidate *sshProcessCandidate, err error) {
	if pid <= 1 || executable == nil {
		return nil, errors.New("invalid SSH process candidate")
	}
	trusted, err := executable.Stat()
	if err != nil {
		return nil, errors.New("trusted SSH executable descriptor is unavailable")
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, errors.New("cannot pin SSH candidate with pidfd")
	}
	process := os.NewFile(uintptr(fd), "ssh-process")
	defer func() {
		if err != nil {
			err = errors.Join(err, process.Close())
		}
	}()
	readStart := func() (uint64, error) {
		file, openErr := os.OpenFile("/proc/"+strconv.Itoa(pid)+"/stat", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if openErr != nil {
			return 0, errors.New("SSH candidate stat is unavailable")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 4097))
		if readErr = errors.Join(readErr, file.Close()); readErr != nil {
			return 0, errors.New("cannot read bounded SSH candidate stat")
		}
		return sshProcessStart(data, pid)
	}
	start, err := readStart()
	if err != nil {
		return nil, err
	}
	procPath := "/proc/" + strconv.Itoa(pid)
	metadata, err := os.Stat(procPath)
	if err != nil {
		return nil, errors.New("SSH candidate ownership is unavailable")
	}
	owner, ok := metadata.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return nil, errors.New("SSH candidate must be root owned")
	}
	// exe is a kernel procfs magic link; inspect its inode, never its contents.
	actual, err := os.Stat(procPath + "/exe")
	if err != nil || !os.SameFile(trusted, actual) {
		return nil, errors.New("SSH candidate executable does not match the pinned binary")
	}
	again, err := readStart()
	if err != nil || again != start {
		return nil, errors.New("SSH candidate changed during identity inspection")
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	if err != nil || n != 0 || poll[0].Revents != 0 {
		return nil, errors.New("pinned SSH candidate exited or became unavailable")
	}
	return &sshProcessCandidate{pidfd: process, pid: pid, start: start}, nil
}

// starttime is field22; comm may itself contain spaces and parentheses.
// This identifies an observed process instance, not an authenticated listener.
func sshProcessStart(data []byte, expectedPID int) (uint64, error) {
	if expectedPID <= 1 || len(data) > 4096 || bytes.IndexByte(data, 0) >= 0 {
		return 0, errors.New("invalid SSH process identity evidence")
	}
	text := strings.TrimSpace(string(data))
	open, close := strings.Index(text, " ("), strings.LastIndex(text, ")")
	if open < 1 || close <= open+2 || close+1 >= len(text) || text[close+1] != ' ' {
		return 0, errors.New("malformed SSH process stat record")
	}
	pid, err := strconv.ParseUint(text[:open], 10, 31)
	if err != nil || pid != uint64(expectedPID) {
		return 0, errors.New("SSH process stat PID does not match the intended process")
	}
	fields := strings.Fields(text[close+1:])
	if len(fields) < 20 || (fields[0] != "R" && fields[0] != "S" && fields[0] != "D") {
		return 0, errors.New("SSH process is terminated, stopped or outside reviewed runtime states")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, errors.New("SSH process start time is unavailable")
	}
	return start, nil
}

// The caller owns the descriptor. Future validation must execute this pinned
// file with fixed arguments and a clean environment, rather than resolve PATH.
func openSSHExecutable() (*os.File, error) {
	const name = "usr/sbin/sshd"
	before, err := secureMutationPath(name, false)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 || before.Mode().Perm()&0111 == 0 || before.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return nil, errors.New("SSH executable must be a regular trusted executable without writable or set-id permissions")
	}
	owner, ok := before.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Nlink != 1 {
		return nil, errors.New("SSH executable ownership or link count requires review")
	}
	file, err := os.OpenFile("/"+name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("cannot pin the trusted SSH executable")
	}
	fail := func(message string) (*os.File, error) {
		return nil, errors.Join(errors.New(message), file.Close())
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return fail("SSH executable changed while opening")
	}
	actualOwner, ok := after.Sys().(*syscall.Stat_t)
	if !ok || actualOwner.Uid != 0 || actualOwner.Nlink != 1 {
		return fail("opened SSH executable ownership is unsafe")
	}
	var magic [4]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil || !bytes.Equal(magic[:], []byte{0x7f, 'E', 'L', 'F'}) {
		return fail("SSH executable is not a reviewed native ELF binary")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail("cannot rewind the pinned SSH executable")
	}
	return file, nil
}

type sshOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (output *sshOutput) Write(data []byte) (int, error) {
	if len(data) > output.limit-output.buffer.Len() {
		return 0, errors.New("SSH subprocess output exceeds reviewed bounds")
	}
	return output.buffer.Write(data)
}

func (output *sshOutput) Bytes() []byte { return output.buffer.Bytes() }

func runSSHProbe(parent context.Context, file *os.File, mode, version string) ([]byte, error) {
	args := []string{"-V"}
	limit := 256
	if mode == "configuration" {
		var err error
		args, err = checks.SSHValidationArgs(version)
		if err != nil {
			return nil, err
		}
		limit = 1024 * 1024
	} else if mode != "version" {
		return nil, errors.New("unapproved SSH probe mode")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	command.ExtraFiles = []*os.File{file}
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/bin", "LC_ALL=C", "LANG=C"}
	command.Dir = "/"
	command.WaitDelay = time.Second
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	stdout := &sshOutput{limit: limit}
	stderr := &sshOutput{limit: 16384}
	command.Stdout, command.Stderr = stdout, stderr
	if mode == "version" {
		command.Stderr = stdout // OpenSSH writes its version banner to stderr.
	}
	if command.Run() != nil {
		return nil, errors.New("trusted SSH probe failed, timed out or exceeded output bounds")
	}
	return stdout.Bytes(), nil
}

// Not yet wired into mutation dispatch. Probe output never reaches core/logs.
func validateSSHConfiguration(ctx context.Context) (results map[string]bool, err error) {
	file, err := openSSHExecutable()
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	version, err := runSSHProbe(ctx, file, "version", "")
	if err != nil {
		return nil, err
	}
	output, err := runSSHProbe(ctx, file, "configuration", string(version))
	if err != nil {
		return nil, err
	}
	return checks.ParseSSHValidation(bytes.NewReader(output))
}
