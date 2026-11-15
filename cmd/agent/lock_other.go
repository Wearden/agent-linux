//go:build !linux

package main

import "errors"

func lockState(string) (func(), error) {
	return nil, errors.New("agent daemon requires Linux")
}
