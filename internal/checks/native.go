package checks

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/Wearden/proto/wire"
)

// Evidence paths are fixed by the embedded catalog. Never follow a configuration
// symlink into an unrelated file, including a credential store.
func nativeStat(system fs.FS, name string) (fs.FileInfo, error) {
	links, ok := system.(fs.ReadLinkFS)
	if !ok {
		return nil, errors.New("filesystem cannot inspect symlinks")
	}
	if !fs.ValidPath(name) {
		return nil, errors.New("invalid evidence path")
	}
	var info fs.FileInfo
	var err error
	current := ""
	for _, part := range strings.Split(name, "/") {
		current = path.Join(current, part)
		info, err = links.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, errors.New("symlinked evidence requires review")
		}
	}
	return info, nil
}

func nativeRead(system fs.FS, name string) (string, error) {
	info, err := nativeStat(system, name)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("evidence is not a regular file")
	}
	f, err := system.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	limit := int64(1024 * 1024)
	if name == "var/lib/dpkg/status" {
		limit = 16 * 1024 * 1024
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > limit {
		return "", errors.New("native evidence exceeds size limit")
	}
	return string(data), nil
}

func result(ok bool, evidence string) (string, string) {
	if ok {
		return wire.Pass, evidence
	}
	return wire.Fail, evidence
}

func sysctlCheck(system fs.FS, rule Rule) (string, string) {
	value, err := nativeRead(system, "proc/sys/"+strings.ReplaceAll(rule.Target, ".", "/"))
	if err != nil {
		return wire.Error, "cannot read runtime kernel parameter"
	}
	expected := "0"
	switch rule.ID {
	case "LNX-NET-009", "LNX-NET-010", "LNX-NET-011":
		expected = "1"
	case "LNX-NET-012":
		expected = "2"
	}
	value = strings.TrimSpace(value)
	if _, err := strconv.ParseUint(value, 10, 32); err != nil {
		return wire.Error, "invalid kernel parameter evidence"
	}
	return result(value == expected, "runtime kernel parameter compared to approved value")
}

func packageCheck(system fs.FS, target string) (string, string) {
	text, err := nativeRead(system, "var/lib/dpkg/status")
	if err != nil {
		return wire.Error, "cannot inspect dpkg status database"
	}
	found, installed := false, true
	for _, block := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n\n") {
		fields := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if line == "" || line[0] == ' ' || line[0] == '\t' {
				continue
			}
			key, value, ok := strings.Cut(line, ":")
			if !ok {
				return wire.Error, "malformed dpkg status database"
			}
			if _, exists := fields[key]; exists {
				return wire.Error, "duplicate dpkg status field"
			}
			fields[key] = strings.TrimSpace(value)
		}
		if fields["Package"] != target {
			continue
		}
		if fields["Status"] == "" {
			return wire.Error, "package record has no status"
		}
		found = true
		installed = installed && fields["Status"] == "install ok installed"
	}
	return result(found && installed, "dpkg package installation status inspected; activation is a separate control")
}

func metadataCheck(system fs.FS, rule Rule) (string, string) {
	info, err := nativeStat(system, strings.TrimPrefix(rule.Target, "/"))
	if err != nil {
		return wire.Error, "cannot inspect file metadata without following symlinks"
	}
	if rule.Target == "/root" {
		if !info.IsDir() {
			return wire.Error, "root home is not a directory"
		}
		return result(info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) == 0 && (info.Mode().Perm() == 0700 || info.Mode().Perm() == 0750), "root directory permission bits inspected without reading its contents")
	}
	if !info.Mode().IsRegular() {
		return wire.Error, "expected a regular evidence file"
	}
	mode := info.Mode().Perm()
	special := info.Mode() & (fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
	if rule.ID == "LNX-LOG-003" {
		return result(special == 0 && (mode == 0640 || mode == 0600 || mode == 0400 || mode == 0), "authentication log permission bits inspected without reading logs")
	}
	want := fs.FileMode(0600)
	groupID := uint32(0)
	switch rule.Target {
	case "/etc/passwd", "/etc/group":
		want = 0644
	case "/etc/sudoers":
		want = 0440
	case "/etc/shadow", "/etc/gshadow":
		want = 0640
		groups, err := nativeRead(system, "etc/group")
		if err != nil {
			return wire.Error, "cannot resolve local shadow group ID"
		}
		count := 0
		for _, line := range strings.Split(groups, "\n") {
			fields := strings.Split(line, ":")
			if len(fields) != 4 || fields[0] != "shadow" {
				continue
			}
			id, err := strconv.ParseUint(fields[2], 10, 32)
			if err != nil {
				return wire.Error, "invalid shadow group ID"
			}
			groupID = uint32(id)
			count++
		}
		if count != 1 {
			return wire.Error, "shadow group ID is absent or ambiguous"
		}
	}
	uid, gid, ok := ownership(info)
	if !ok {
		return wire.Error, "filesystem does not expose native owner metadata"
	}
	return result(mode == want && special == 0 && uid == 0 && gid == groupID, "permission and numeric ownership metadata inspected; file content was not read")
}

func uidZero(system fs.FS) (string, string) {
	text, err := nativeRead(system, "etc/passwd")
	if err != nil {
		return wire.Error, "cannot inspect local account UID metadata"
	}
	count := 0
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 || strings.HasPrefix(fields[0], "+") || strings.HasPrefix(fields[0], "-") {
			return wire.Error, "account database requires external identity review"
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil {
			return wire.Error, "invalid account UID"
		}
		if uid == 0 {
			if fields[0] != "root" {
				return wire.Fail, "a non-root account has local UID zero"
			}
			count++
		}
	}
	return result(count == 1, "local passwd database contains exactly one root UID-zero entry; external NSS identities are outside this control")
}

func uncomment(line string) string { return strings.TrimSpace(strings.SplitN(line, "#", 2)[0]) }

func sshConfig(system fs.FS) (map[string]string, error) {
	values := map[string]string{}
	visited := map[string]bool{}
	var load func(string) error
	load = func(name string) error {
		if visited[name] || len(visited) >= 128 {
			return errors.New("recursive or oversized SSH includes")
		}
		visited[name] = true
		text, err := nativeRead(system, name)
		if err != nil {
			return err
		}
		for _, raw := range strings.Split(text, "\n") {
			line := uncomment(raw)
			if line == "" {
				continue
			}
			if strings.ContainsAny(line, "\\\"'\x00") {
				return errors.New("complex SSH quoting requires review")
			}
			line = strings.Replace(line, "=", " ", 1)
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return errors.New("malformed SSH directive")
			}
			key := strings.ToLower(fields[0])
			if key == "match" {
				return errors.New("conditional SSH Match policy requires connection-specific evaluation")
			}
			if key == "include" {
				if len(fields) != 2 || fields[1] != "/etc/ssh/sshd_config.d/*.conf" {
					return errors.New("SSH Include path is outside reviewed config directory")
				}
				entries, err := nativeEntries(system, "etc/ssh/sshd_config.d", true)
				if err != nil {
					return err
				}
				for _, entry := range entries {
					if strings.HasSuffix(entry.Name(), ".conf") {
						if err := load("etc/ssh/sshd_config.d/" + entry.Name()); err != nil {
							return err
						}
					}
				}
				continue
			}
			if _, exists := values[key]; !exists {
				values[key] = strings.Join(fields[1:], " ")
			}
		}
		return nil
	}
	return values, load("etc/ssh/sshd_config")
}

func sshCheck(system fs.FS, target string) (string, string) {
	values, err := sshConfig(system)
	if err != nil {
		return wire.Error, "SSH configuration is unreadable, conditional, or outside the reviewed include/grammar subset"
	}
	value, exists := values[target]
	if !exists {
		return wire.Error, "SSH option is implicit; compiled defaults and daemon launch overrides require review"
	}
	value = strings.ToLower(value)
	ok := false
	switch target {
	case "loglevel":
		ok = value == "info" || value == "verbose"
	case "ignorerhosts", "usepam":
		ok = value == "yes"
	case "x11forwarding", "hostbasedauthentication", "permitrootlogin", "permitemptypasswords", "permituserenvironment":
		ok = value == "no"
	case "banner":
		ok = value == "/etc/issue.net"
	default:
		limits := map[string]int{"maxauthtries": 4, "clientaliveinterval": 300, "clientalivecountmax": 3, "logingracetime": 60, "maxsessions": 10}
		limit, exists := limits[target]
		if !exists {
			return wire.Error, "unknown SSH option"
		}
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return wire.Error, "SSH numeric option is outside reviewed grammar"
		}
		ok = n <= limit
		// Zero disables the intended idle/login timeout.
		if target == "clientaliveinterval" || target == "logingracetime" {
			ok = ok && n > 0
		}
	}
	return result(ok, "explicit SSH file policy inspected with first-value precedence; running daemon state and launch overrides are not attested")
}

func nativeEntries(system fs.FS, name string, optional bool) ([]fs.DirEntry, error) {
	info, err := nativeStat(system, name)
	if optional && isMissing(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("evidence directory is not a directory")
	}
	entries, err := fs.ReadDir(system, name)
	if len(entries) > 1024 {
		return nil, errors.New("evidence directory exceeds entry limit")
	}
	return entries, err
}

func policyCheck(system fs.FS, key string) (string, string) {
	name := "etc/security/pwquality.conf"
	limit, lower := -1, false
	switch key {
	case "minlen":
		limit, lower = 14, true
	case "deny":
		name, limit = "etc/security/faillock.conf", 5
	case "PASS_MAX_DAYS":
		name, limit = "etc/login.defs", 365
	case "PASS_MIN_DAYS":
		name, limit, lower = "etc/login.defs", 1, true
	case "dcredit", "ucredit", "lcredit", "ocredit":
	default:
		return wire.Error, "unknown password policy setting"
	}
	if name == "etc/security/pwquality.conf" {
		entries, err := nativeEntries(system, "etc/security/pwquality.conf.d", true)
		if err != nil {
			return wire.Error, "cannot inspect password quality drop-ins"
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".conf") {
				return wire.Error, "password quality drop-ins require merged policy evaluation"
			}
		}
	}
	text, err := nativeRead(system, name)
	if err != nil {
		return wire.Error, "cannot read password policy configuration"
	}
	value, found := "", false
	for _, raw := range strings.Split(text, "\n") {
		line := uncomment(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(strings.Replace(line, "=", " ", 1))
		if len(fields) == 0 || fields[0] != key {
			continue
		}
		if len(fields) != 2 {
			return wire.Error, "malformed password policy value"
		}
		value, found = fields[1], true
	}
	if !found {
		return wire.Error, "password policy value is implicit or absent"
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return wire.Error, "invalid password policy numeric value"
	}
	ok := n <= limit
	if lower {
		ok = n >= limit
	}
	if key == "deny" || key == "PASS_MAX_DAYS" {
		ok = ok && n > 0
	}
	return result(ok, "explicit configuration value inspected; PAM stack activation and existing-account aging are separate from this file policy control")
}

func journalCheck(system fs.FS, key string) (string, string) {
	var files []string
	for _, dir := range []string{"etc", "run", "usr/local/lib", "usr/lib"} {
		name := dir + "/systemd/journald.conf"
		if _, err := nativeStat(system, name); err == nil {
			files = append(files, name)
			break
		} else if !isMissing(err) {
			return wire.Error, "cannot inspect journal main configuration"
		}
	}
	selected := map[string]string{}
	for _, dir := range []string{"etc", "run", "usr/local/lib", "usr/lib"} {
		base := dir + "/systemd/journald.conf.d"
		entries, err := nativeEntries(system, base, true)
		if err != nil {
			return wire.Error, "cannot inspect journal configuration drop-ins"
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".conf") {
				if _, exists := selected[entry.Name()]; !exists {
					selected[entry.Name()] = base + "/" + entry.Name()
				}
			}
		}
	}
	names := make([]string, 0, len(selected))
	for name := range selected {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		files = append(files, selected[name])
	}
	value, found := "", false
	for _, name := range files {
		text, err := nativeRead(system, name)
		if err != nil {
			return wire.Error, "cannot read journal configuration without following symlinks"
		}
		section := ""
		for _, raw := range strings.Split(text, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.ContainsAny(line, "\\\x00") {
				return wire.Error, "complex journal configuration requires review"
			}
			if strings.HasPrefix(line, "[") {
				if !strings.HasSuffix(line, "]") {
					return wire.Error, "malformed journal section"
				}
				section = strings.Trim(line, "[]")
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				return wire.Error, "malformed journal configuration"
			}
			if section == "Journal" && strings.TrimSpace(k) == key {
				value, found = strings.TrimSpace(v), true
			}
		}
	}
	if !found {
		return wire.Error, "journal setting is implicit or absent"
	}
	want := "persistent"
	if key == "Compress" {
		want = "yes"
	}
	return result(value == want, "merged journal file policy inspected; running daemon reload state is not attested")
}

func aptHTTPS(system fs.FS) (string, string) {
	files := []string{}
	if _, err := nativeStat(system, "etc/apt/sources.list"); err == nil {
		files = append(files, "etc/apt/sources.list")
	} else if !isMissing(err) {
		return wire.Error, "cannot inspect apt sources"
	}
	entries, err := nativeEntries(system, "etc/apt/sources.list.d", true)
	if err != nil {
		return wire.Error, "cannot inspect apt source directory"
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".list") || strings.HasSuffix(entry.Name(), ".sources") {
			files = append(files, "etc/apt/sources.list.d/"+entry.Name())
		}
	}
	found := false
	for _, name := range files {
		text, err := nativeRead(system, name)
		if err != nil {
			return wire.Error, "cannot read apt sources without following symlinks"
		}
		uriContinuation := false
		for _, raw := range strings.Split(text, "\n") {
			line := uncomment(raw)
			if line == "" {
				continue
			}
			if strings.Contains(line, "http://") {
				return wire.Fail, "an unencrypted HTTP apt source is configured"
			}
			if strings.Contains(line, "mirror:") || strings.Contains(line, "mirror+") || strings.Contains(line, "$") || strings.ContainsAny(line, "\\\x00") {
				return wire.Error, "indirect or complex apt sources require review"
			}
			var uris []string
			if strings.HasSuffix(name, ".sources") {
				if strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t") {
					if uriContinuation {
						uris = strings.Fields(line)
					}
				} else {
					key, value, ok := strings.Cut(line, ":")
					if !ok {
						return wire.Error, "malformed deb822 apt source"
					}
					uriContinuation = strings.EqualFold(key, "URIs")
					if uriContinuation {
						uris = strings.Fields(value)
					}
				}
			} else {
				fields := strings.Fields(line)
				if len(fields) < 3 || (fields[0] != "deb" && fields[0] != "deb-src") {
					return wire.Error, "unrecognized apt source syntax"
				}
				remaining := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
				if strings.HasPrefix(remaining, "[") {
					_, tail, ok := strings.Cut(remaining, "]")
					if !ok {
						return wire.Error, "malformed apt source options"
					}
					remaining = strings.TrimSpace(tail)
				}
				fields = strings.Fields(remaining)
				if len(fields) < 2 {
					return wire.Error, "incomplete apt source"
				}
				uris = []string{fields[0]}
			}
			for _, address := range uris {
				u, err := url.Parse(address)
				if err != nil || u.Hostname() == "" || u.User != nil || u.Scheme != "https" {
					return wire.Error, "apt URI is outside reviewed credential-free HTTPS source syntax"
				}
				found = true
			}
		}
	}
	if !found {
		return wire.Error, "no explicit HTTPS apt source evidence"
	}
	return wire.Pass, "reviewed apt source files contain HTTPS and no HTTP references; package signature policy is a separate control"
}

func serviceDisabled(system fs.FS, targets string) (string, string) {
	links, ok := system.(fs.ReadLinkFS)
	if !ok {
		return wire.Error, "filesystem cannot inspect unit symlinks"
	}
	for _, target := range strings.Split(targets, ",") {
		masked := false
		for _, base := range []string{"etc/systemd/system", "run/systemd/system"} {
			info, err := links.Lstat(base + "/" + target)
			if isMissing(err) {
				continue
			}
			if err != nil {
				return wire.Error, "cannot inspect service unit override"
			}
			if info.Mode()&fs.ModeSymlink != 0 {
				to, err := links.ReadLink(base + "/" + target)
				if err != nil {
					return wire.Error, "cannot read service unit link"
				}
				if to == "/dev/null" {
					masked = true
					break
				}
				return wire.Error, "service alias or linked unit requires systemd manager evaluation"
			}
			break
		}
		if masked {
			continue
		}
		for _, base := range []string{"etc/systemd/system", "run/systemd/system"} {
			entries, err := nativeEntries(system, base, true)
			if err != nil {
				return wire.Error, "cannot inspect unit enablement directory"
			}
			for _, entry := range entries {
				if !strings.HasSuffix(entry.Name(), ".wants") && !strings.HasSuffix(entry.Name(), ".requires") {
					continue
				}
				children, err := nativeEntries(system, base+"/"+entry.Name(), false)
				if err != nil {
					return wire.Error, "cannot inspect unit dependencies"
				}
				for _, child := range children {
					if child.Name() == target {
						return wire.Fail, "unit is linked from a persistent or runtime enablement dependency"
					}
				}
			}
		}
		return wire.Error, "unit is not explicitly masked; disabled/static/generated and alternate systemd lookup paths require manager evaluation"
	}
	return wire.Pass, "all named units are explicitly masked; mask evidence does not attest whether an already running service was stopped"
}

// Persistent UFW policy cannot prove what is currently loaded in netfilter.
// Keep these controls in error even when the reviewed file setting is present.
func ufwEvidence(system fs.FS, id string) string {
	name, key, expected := "etc/ufw/ufw.conf", "ENABLED", "yes"
	switch id {
	case "LNX-FW-002":
		name, key, expected = "etc/default/ufw", "DEFAULT_INPUT_POLICY", "DROP"
	case "LNX-FW-003":
		name, key, expected = "etc/default/ufw", "DEFAULT_OUTPUT_POLICY", "DROP"
	case "LNX-FW-004":
		return "unsupported: SSH allow rules need live IPv4/IPv6 netfilter evaluation; static UFW rules cannot prove access"
	case "LNX-FW-006":
		key, expected = "LOGLEVEL", "enabled-log-level"
	case "LNX-FW-005":
	default:
		return unsupportedReason(id)
	}
	text, err := nativeRead(system, name)
	if err != nil {
		return "unsupported: UFW runtime evaluation is unavailable and persistent policy is unreadable"
	}
	value, count := "", 0
	for _, raw := range strings.Split(text, "\n") {
		line := uncomment(raw)
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && ((v[0] == 34 && v[len(v)-1] == 34) || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		value = v
		count++
	}
	if count != 1 {
		return "unsupported: UFW persistent setting is missing or ambiguous; live runtime state is not evaluated"
	}
	configured := value == expected
	if id == "LNX-FW-006" {
		configured = value == "low" || value == "medium" || value == "high" || value == "full"
	}
	if configured {
		return "unsupported: reviewed persistent UFW policy matches the control, but loaded runtime state cannot be established"
	}
	return "unsupported: reviewed persistent UFW policy does not match the control; loaded runtime state cannot be established"
}

func unsupportedReason(id string) string {
	switch {
	case strings.HasPrefix(id, "LNX-FW-"):
		return "unsupported: live UFW/netfilter rules, activation and logging require a reviewed native runtime evaluator"
	case id == "LNX-PKG-005":
		return "unsupported: effective apt authentication policy requires complete apt configuration/include evaluation"
	case id == "LNX-LOG-006":
		return "unsupported: sudo logging requires full sudoers include, scope and precedence evaluation"
	case id == "LNX-PAM-007":
		return "unsupported: password history requires complete PAM stack and module policy evaluation"
	case id == "LNX-USR-006":
		return "unsupported: full legacy-account audit includes credential-file contents, which this agent does not read"
	case id == "LNX-USR-007" || id == "LNX-USR-008" || id == "LNX-USR-009":
		return "unsupported: whole-filesystem traversal and ownership/NSS applicability need a bounded native audit design"
	}
	return fmt.Sprintf("unsupported native control: %s", id)
}
