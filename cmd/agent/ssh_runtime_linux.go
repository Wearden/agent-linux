package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/Wearden/agent-linux/internal/checks"
)

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
