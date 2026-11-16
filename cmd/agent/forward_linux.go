package main

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
)

// Writing net.ipv4.ip_forward makes the kernel (inet_forward_change) rewrite every
// interface's forwarding value and conf/all/accept_redirects. The pre-change
// values are journaled next to the single-parameter snapshot and re-applied
// after it is restored. shortcut: other kernel side effects (IPv6, LRO, netconf
// notifications) are not journaled; extend this list if inet_forward_change grows.
const forwardingRoot = "proc/sys/net/ipv4/conf"
const acceptRedirectsAll = forwardingRoot + "/all/accept_redirects"

func forwardingPath(name string) string { return forwardingRoot + "/" + name + "/forwarding" }

func validInterfaceDir(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 64 && !strings.ContainsAny(name, "/\x00")
}

// A journal key is only accepted if it is one of the two fixed path shapes.
func validForwardKey(key string) bool {
	if key == acceptRedirectsAll {
		return true
	}
	name, ok := strings.CutPrefix(key, forwardingRoot+"/")
	if !ok {
		return false
	}
	name, ok = strings.CutSuffix(name, "/forwarding")
	return ok && validInterfaceDir(name)
}

func readNumeric(key string) (string, error) {
	if _, err := secureMutationPath(key, false); err != nil {
		return "", err
	}
	data, err := os.ReadFile("/" + key)
	if err != nil {
		return "", errors.New("cannot read forwarding-related kernel setting")
	}
	text := strings.TrimSpace(string(data))
	if _, err := strconv.ParseUint(text, 10, 32); err != nil {
		return "", errors.New("forwarding-related kernel value is not numeric")
	}
	return text + "\n", nil
}

func snapshotForwarding() ([]byte, error) {
	if _, err := secureMutationPath(forwardingRoot, false); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir("/" + forwardingRoot)
	if err != nil || len(entries) > 512 {
		return nil, errors.New("cannot enumerate bounded per-interface forwarding settings")
	}
	values := map[string]string{}
	keys := []string{acceptRedirectsAll}
	for _, entry := range entries {
		if !validInterfaceDir(entry.Name()) {
			return nil, errors.New("unexpected interface name in forwarding settings")
		}
		keys = append(keys, forwardingPath(entry.Name()))
	}
	for _, key := range keys {
		if values[key], err = readNumeric(key); err != nil {
			return nil, err
		}
	}
	return json.Marshal(values)
}

// accept_redirects is restored before the per-interface values. Interfaces that
// disappeared since the snapshot are skipped; any other write failure is
// reported so recovery is not claimed complete.
func restoreForwarding(extra []byte) error {
	var values map[string]string
	if len(extra) == 0 || json.Unmarshal(extra, &values) != nil || len(values) > 514 {
		return errors.New("invalid or absent forwarding journal")
	}
	if _, ok := values[acceptRedirectsAll]; !ok {
		return errors.New("forwarding journal lacks accept_redirects")
	}
	order := []string{acceptRedirectsAll}
	for key := range values {
		if !validForwardKey(key) {
			return errors.New("invalid journaled forwarding key")
		}
		if key != acceptRedirectsAll {
			order = append(order, key)
		}
	}
	for _, key := range order {
		if _, err := os.Lstat("/" + key); errors.Is(err, os.ErrNotExist) && key != acceptRedirectsAll {
			continue
		}
		if err := writeSysctl(key, []byte(values[key])); err != nil {
			return err
		}
	}
	return nil
}
