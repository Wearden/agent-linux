package checks

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/Wearden/proto/wire"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
)

type Rule struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	Severity string `json:"severity"`
}

func Run(system fs.FS, rules []Rule) []wire.Finding {
	findings := make([]wire.Finding, 0, len(rules))
	var firewall map[string]wire.Finding
	for _, r := range rules {
		status, evidence := wire.Error, "unsupported native check"
		switch r.Kind {
		case "kernel_module":
			status, evidence = module(system, r.Target)
		case "mount_options":
			status, evidence = mount(system, r.Target)
		case "sysctl":
			status, evidence = sysctlCheck(system, r)
		case "package_installed":
			status, evidence = packageCheck(system, r.Target)
		case "file_metadata":
			status, evidence = metadataCheck(system, r)
		case "sshd_config":
			status, evidence = sshCheck(system, r.Target)
		case "policy_config":
			status, evidence = policyCheck(system, r.Target)
		case "journald_config":
			status, evidence = journalCheck(system, r.Target)
		case "apt_https":
			status, evidence = aptHTTPS(system)
		case "uid_zero":
			status, evidence = uidZero(system)
		case "service_disabled":
			status, evidence = serviceDisabled(system, r.Target)
		case "apt_authentication":
			status, evidence = aptAuthentication(system)
		case "sudo_logfile":
			status, evidence = sudoLogfile(system)
		case "pam_history":
			status, evidence = pamHistory(system)
		case "filesystem_metadata":
			status, evidence = filesystemAudit(system, r.Target)
		case "ufw_runtime":
			if firewall == nil {
				firewall = observeUFW(system)
			}
			if observation, ok := firewall[r.Target]; ok {
				status, evidence = observation.Status, observation.Evidence
			}
		case "unsupported":
			evidence = unsupportedReason(r.ID)
			if strings.HasPrefix(r.ID, "LNX-FW-") {
				evidence = ufwEvidence(system, r.ID)
			}
		}
		findings = append(findings, wire.Finding{RuleID: r.ID, Status: status, Severity: r.Severity, Evidence: evidence})
	}
	return findings
}
func read(system fs.FS, name string) (string, error) {
	f, err := system.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4*1024*1024+1))
	if err != nil {
		return "", err
	}
	if len(data) > 4*1024*1024 {
		return "", fmt.Errorf("evidence file too large")
	}
	return string(data), nil
}
func normalize(name string) string { return strings.ReplaceAll(name, "-", "_") }
func module(system fs.FS, target string) (string, string) {
	loaded, err := read(system, "proc/modules")
	if err != nil {
		return wire.Error, "cannot read loaded module state"
	}
	for _, line := range strings.Split(loaded, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && normalize(f[0]) == normalize(target) {
			return wire.Fail, "module is currently loaded"
		}
	}
	if info, err := fs.Stat(system, "sys/module"); err != nil || !info.IsDir() {
		return wire.Error, "module sysfs directory is unavailable"
	}
	// Built-in modules are absent from /proc/modules but may still be active.
	if _, err := fs.Stat(system, "sys/module/"+normalize(target)); err == nil {
		return wire.Fail, "module is present in sysfs"
	} else if !isMissing(err) {
		return wire.Error, "cannot inspect module sysfs state"
	}
	files := map[string]string{}
	for _, dir := range []string{"etc/modprobe.d", "run/modprobe.d", "usr/local/lib/modprobe.d", "usr/lib/modprobe.d", "lib/modprobe.d"} {
		entries, err := fs.ReadDir(system, dir)
		if isMissing(err) {
			continue
		}
		if err != nil {
			return wire.Error, "cannot read modprobe configuration directory"
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}
			if _, exists := files[entry.Name()]; !exists {
				files[entry.Name()] = dir + "/" + entry.Name()
			}
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	blacklisted := false
	install := ""
	for _, name := range names {
		if _, ok := system.(fs.ReadLinkFS); ok {
			if _, err := nativeStat(system, files[name]); err != nil {
				return wire.Error, "modprobe evidence follows a symlink or is unavailable"
			}
		}
		text, err := read(system, files[name])
		if err != nil {
			return wire.Error, "cannot read modprobe configuration file"
		}
		scanner := bufio.NewScanner(strings.NewReader(text))
		for scanner.Scan() {
			line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
			if line == "" {
				continue
			}
			if strings.HasSuffix(line, "\\") {
				return wire.Error, "continued modprobe directives require review"
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return wire.Error, "malformed modprobe configuration"
			}
			if fields[0] == "include" {
				return wire.Error, "included modprobe configuration is unsupported"
			}
			if fields[0] == "alias" && len(fields) >= 3 && (normalize(fields[1]) == normalize(target) || normalize(fields[2]) == normalize(target)) {
				return wire.Error, "module alias requires native applicability review"
			}
			if strings.ContainsAny(fields[1], "*?[") && (fields[0] == "install" || fields[0] == "alias" || fields[0] == "blacklist" || fields[0] == "softdep") {
				return wire.Error, "wildcard module directive requires native review"
			}
			if normalize(fields[1]) != normalize(target) {
				continue
			}
			switch fields[0] {
			case "softdep":
				return wire.Error, "softdep interaction requires kmod version review"
			case "blacklist":
				if len(fields) != 2 {
					return wire.Error, "malformed blacklist directive"
				}
				blacklisted = true
			case "install":
				command := strings.Join(fields[2:], " ")
				if command == "" || (install != "" && install != command) {
					return wire.Error, "conflicting or malformed install directives"
				}
				install = command
			}
		}
		if scanner.Err() != nil {
			return wire.Error, "cannot parse modprobe configuration"
		}
	}
	if install != "" && install != "/bin/true" && install != "/bin/false" && install != "/usr/bin/true" && install != "/usr/bin/false" {
		return wire.Error, "install directive is not a reviewed blocking command"
	}
	if !blacklisted || install == "" {
		return wire.Fail, "requires both blacklist and install blocking"
	}
	return wire.Pass, "module is not loaded; blacklist and blocking install directive found"
}
func isMissing(err error) bool { return errors.Is(err, fs.ErrNotExist) }
func unescapeMount(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 >= len(s) {
			return "", fmt.Errorf("bad mount escape")
		}
		v := s[i+1 : i+4]
		switch v {
		case "040":
			b.WriteByte(' ')
		case "011":
			b.WriteByte('\t')
		case "012":
			b.WriteByte('\n')
		case "134":
			b.WriteByte('\\')
		default:
			return "", fmt.Errorf("unknown mount escape")
		}
		i += 3
	}
	return b.String(), nil
}
func mount(system fs.FS, target string) (string, string) {
	links, ok := system.(fs.ReadLinkFS)
	if !ok {
		return wire.Error, "filesystem cannot inspect mount target symlinks"
	}
	current := ""
	for _, part := range strings.Split(strings.TrimPrefix(target, "/"), "/") {
		current = path.Join(current, part)
		info, err := links.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
			return wire.Error, "mount target is missing, inaccessible or follows a symlink"
		}
	}

	text, err := read(system, "proc/self/mountinfo")
	if err != nil {
		return wire.Error, "cannot read mountinfo"
	}
	longest := -1
	selected := ""
	ambiguous := false
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			return wire.Error, "malformed mountinfo"
		}
		fields := strings.Fields(parts[0])
		if len(fields) < 6 || len(strings.Fields(parts[1])) < 3 {
			return wire.Error, "malformed mountinfo"
		}
		mountpoint, err := unescapeMount(fields[4])
		if err != nil || !path.IsAbs(mountpoint) {
			return wire.Error, "invalid mount path"
		}
		if target != mountpoint && mountpoint != "/" && !strings.HasPrefix(target, strings.TrimRight(mountpoint, "/")+"/") {
			continue
		}
		if len(mountpoint) > longest {
			longest = len(mountpoint)
			selected = fields[5]
			ambiguous = false
		} else if len(mountpoint) == longest {
			ambiguous = true
		}
	}
	if longest < 0 || ambiguous {
		return wire.Error, "mount selection is missing or ambiguous"
	}
	options := map[string]bool{}
	for _, o := range strings.Split(selected, ",") {
		options[o] = true
	}
	for _, o := range []string{"nodev", "nosuid", "noexec"} {
		if !options[o] {
			return wire.Fail, "effective mount is missing one or more required safety options"
		}
	}
	return wire.Pass, "effective mount has nodev, nosuid and noexec"
}
