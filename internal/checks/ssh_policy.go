package checks

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"strconv"
	"strings"
)

// ParseSSHValidation consumes configuration-only output, never a daemon/key
// check. Results describe option comparisons, not loaded daemon or banner state.
func ParseSSHValidation(reader io.Reader) (map[string]bool, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return nil, errors.New("SSH validation output is unavailable or exceeds1 MiB")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 65536)
	results := make(map[string]bool, len(sshBaselines))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.ContainsRune(line, 0) {
			return nil, errors.New("SSH validation output contains NUL")
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		option := strings.ToLower(fields[0])
		baseline, known := SSHBaseline(option)
		if !known {
			continue
		}
		if _, exists := results[option]; exists || len(fields) != 2 {
			return nil, errors.New("duplicate or malformed selected SSH validation option")
		}
		value := strings.ToLower(fields[1])
		pass := value == strings.ToLower(baseline)
		switch option {
		case "loglevel":
			pass = value == "info" || value == "verbose"
		case "maxauthtries", "clientaliveinterval", "clientalivecountmax", "logingracetime", "maxsessions":
			actual, err := strconv.ParseUint(value, 10, 32)
			limit, limitErr := strconv.ParseUint(baseline, 10, 32)
			if err != nil || limitErr != nil {
				return nil, errors.New("invalid selected SSH validation numeric value")
			}
			pass = actual <= limit
			if option == "clientaliveinterval" || option == "logingracetime" {
				pass = pass && actual > 0
			}
		}
		results[option] = pass
	}
	if scanner.Err() != nil {
		return nil, errors.New("cannot read bounded SSH validation output")
	}
	if len(results) != len(sshBaselines) {
		return nil, errors.New("SSH validation output lacks required policy options")
	}
	return results, nil
}

// Shared by observations and typed mutation planning. Callers cannot introduce
// network-provided SSH options or replacement values into this baseline.
var sshBaselines = map[string]string{
	"loglevel": "INFO", "x11forwarding": "no", "maxauthtries": "4",
	"ignorerhosts": "yes", "hostbasedauthentication": "no",
	"permitrootlogin": "no", "permitemptypasswords": "no",
	"permituserenvironment": "no", "clientaliveinterval": "300",
	"clientalivecountmax": "3", "logingracetime": "60", "maxsessions": "10",
	"usepam": "yes", "banner": "/etc/issue.net",
}

func SSHBaseline(option string) (string, bool) {
	value, ok := sshBaselines[option]
	return value, ok
}

// SSHDropInDirective prepares only a compiled directive after checking the
// existing include grammar. The caller must still back up, write, recheck and
// recover it; an earlier included file can win first-value precedence.
func SSHDropInDirective(system fs.FS, option string) (string, error) {
	value, known := SSHBaseline(option)
	if !known {
		return "", errors.New("SSH option is outside the compiled mutation baseline")
	}
	text, err := nativeRead(system, "etc/ssh/sshd_config")
	if err != nil {
		return "", errors.New("cannot safely inspect the SSH include position")
	}
	if _, err := sshConfig(system); err != nil {
		return "", errors.New("SSH configuration is conditional, unreadable or outside the reviewed grammar")
	}
	current, err := nativeRead(system, "etc/ssh/sshd_config")
	if err != nil || current != text {
		return "", errors.New("main SSH configuration changed during drop-in preparation")
	}
	for _, raw := range strings.Split(text, "\n") {
		line := uncomment(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(strings.Replace(line, "=", " ", 1))
		if len(fields) < 2 {
			return "", errors.New("malformed SSH directive while checking include precedence")
		}
		key := strings.ToLower(fields[0])
		if key == option {
			return "", errors.New("main-file SSH option precedes the managed include; drop-in cannot override it")
		}
		if key == "include" && len(fields) == 2 && fields[1] == "/etc/ssh/sshd_config.d/*.conf" {
			return option + " " + value + "\n", nil
		}
	}
	return "", errors.New("standard SSH drop-in include is absent")
}
