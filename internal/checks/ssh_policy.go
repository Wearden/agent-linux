package checks

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
