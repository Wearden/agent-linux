package main

import (
	"bytes"
	"errors"
	"io/fs"
	"strings"

	"github.com/Wearden/agent-linux/internal/checks"
)

func policyPlan(rule checks.Rule) (mutationPlan, error) {
	p := mutationPlan{Kind: "policy", Path: "etc/security/pwquality.conf"}
	value := "-1"
	switch rule.ID {
	case "LNX-PAM-002":
		value = "14"
	case "LNX-PAM-003", "LNX-PAM-004", "LNX-PAM-005", "LNX-PAM-006":
	case "LNX-PAM-008":
		p.Path, value = "etc/security/faillock.conf", "5"
	case "LNX-PAM-009":
		p.Path, value = "etc/login.defs", "365"
	case "LNX-PAM-010":
		p.Path, value = "etc/login.defs", "1"
	default:
		return p, errors.New("password policy has no reviewed mutation plan")
	}
	p.Payload = "# Wearden " + rule.ID + "\n" + rule.Target + " = " + value + "\n"
	if p.Path == "etc/login.defs" {
		p.Payload = "# Wearden " + rule.ID + "\n" + rule.Target + " " + value + "\n"
	}
	return p, nil
}

func policySelected(data []byte, key string) string {
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.Replace(strings.SplitN(line, "#", 2)[0], "=", " ", 1))
		if len(fields) > 0 && strings.EqualFold(fields[0], key) {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func applyPolicy(backup *ruleBackup, p mutationPlan, rule checks.Rule) error {
	if !backup.Exists || bytes.IndexByte(backup.Data, 0) >= 0 || len(backup.Data)+len(p.Payload) > 1024*1024 || (len(backup.Data) > 0 && backup.Data[len(backup.Data)-1] != '\n') {
		return errors.New("policy file must exist, be bounded text and end on a complete line")
	}
	if bytes.Contains(backup.Data, []byte("# Wearden "+rule.ID)) {
		return errors.New("policy already contains this managed control; review the retained run before replacing it")
	}
	for _, line := range bytes.Split(backup.Data, []byte{'\n'}) {
		if len(line) > 1023 {
			return errors.New("policy configuration line exceeds reviewed native parser bounds")
		}
	}
	current, err := snapshotMutation(p.Path, "file")
	if err != nil || !current.Exists || current.Mode != backup.Mode || current.UID != backup.UID || current.GID != backup.GID || !bytes.Equal(current.Data, backup.Data) {
		return errors.New("policy changed after its durable snapshot")
	}
	data := append(append([]byte(nil), backup.Data...), []byte(p.Payload)...)
	return writeManaged(p.Path, data, fs.FileMode(backup.Mode), backup.UID, backup.GID)
}

// Remove only this control's exact appended block, preserving other controls
// in the same file regardless of rollback order. Refuse selected-option drift.
func restorePolicy(backup *ruleBackup, p mutationPlan, rule checks.Rule) error {
	if !backup.Exists || backup.Companion != nil || backup.ParentCreated {
		return errors.New("invalid policy backup shape")
	}
	current, err := snapshotMutation(p.Path, "file")
	if err != nil || !current.Exists || current.Mode != backup.Mode || current.UID != backup.UID || current.GID != backup.GID {
		return errors.New("policy recovery metadata changed externally")
	}
	if bytes.Equal(current.Data, backup.Data) {
		return nil // Apply may have been interrupted before the atomic rename.
	}
	block := []byte(p.Payload)
	count := bytes.Count(current.Data, block)
	if count > 1 {
		return errors.New("managed policy block is ambiguous")
	}
	restored := current.Data
	if count == 1 {
		i := bytes.Index(current.Data, block)
		if i > 0 && current.Data[i-1] != '\n' {
			return errors.New("managed policy block is not on a line boundary")
		}
		restored = bytes.Replace(current.Data, block, nil, 1)
	}
	if bytes.Contains(restored, []byte("# Wearden "+rule.ID)) || policySelected(restored, rule.Target) != policySelected(backup.Data, rule.Target) {
		return errors.New("selected policy setting changed externally; refusing recovery overwrite")
	}
	if count == 0 {
		return nil
	}
	if err := writeManaged(p.Path, restored, fs.FileMode(backup.Mode), backup.UID, backup.GID); err != nil {
		return err
	}
	after, err := snapshotMutation(p.Path, "file")
	if err != nil || !bytes.Equal(after.Data, restored) || after.Mode != backup.Mode || after.UID != backup.UID || after.GID != backup.GID {
		return errors.New("policy recovery did not match the intended local state")
	}
	return nil
}
