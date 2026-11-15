package main

import (
	"errors"
	"os"
	"syscall"
)

func lockState(dir string) (func(), error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("state directory is already in use or does not support locking")
	}
	return func() { f.Close() }, nil
}
