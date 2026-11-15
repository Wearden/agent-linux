package checks

import (
	"errors"
	"io/fs"
	"strings"
)

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
