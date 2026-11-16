package checks

import (
	"errors"
	"io/fs"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/Wearden/proto/wire"
)

type policyToken struct {
	value  string
	symbol byte
	quoted bool
}

// This parser never opens #include/#clear targets or interprets executable values.
func aptTokens(text string) ([]policyToken, error) {
	tokens := []policyToken{}
	for i := 0; i < len(text); {
		c := text[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			i++
			continue
		}
		if c == '#' {
			// Only #include and #clear are directives; every other #-line is a comment.
			if strings.HasPrefix(text[i:], "#include") || strings.HasPrefix(text[i:], "#clear") {
				return nil, errors.New("apt preprocessor directive requires review")
			}
			for i < len(text) && text[i] != '\n' {
				i++
			}
			continue
		}
		if i+1 < len(text) && text[i:i+2] == "//" {
			for i < len(text) && text[i] != '\n' {
				i++
			}
			continue
		}
		if i+1 < len(text) && text[i:i+2] == "/*" {
			end := strings.Index(text[i+2:], "*/")
			if end < 0 {
				return nil, errors.New("unterminated apt comment")
			}
			i += end + 4
			continue
		}
		if strings.ContainsRune("{};", rune(c)) {
			tokens = append(tokens, policyToken{symbol: c})
			i++
			continue
		}
		if c == '"' {
			i++
			var value strings.Builder
			closed := false
			for i < len(text) {
				if text[i] == '"' {
					i++
					closed = true
					break
				}
				if text[i] == '\\' {
					i++
					if i >= len(text) || (text[i] != '"' && text[i] != '\\') {
						return nil, errors.New("complex apt escape requires review")
					}
				}
				if text[i] == 0 || text[i] == '\n' {
					return nil, errors.New("invalid apt string")
				}
				value.WriteByte(text[i])
				i++
			}
			if !closed {
				return nil, errors.New("unterminated apt string")
			}
			tokens = append(tokens, policyToken{value: value.String(), quoted: true})
		} else {
			start := i
			for i < len(text) && !strings.ContainsRune(" \t\r\n{};", rune(text[i])) {
				if strings.ContainsRune("#\\\"\x00", rune(text[i])) {
					return nil, errors.New("unsupported apt token")
				}
				i++
			}
			if start == i {
				return nil, errors.New("invalid apt token")
			}
			tokens = append(tokens, policyToken{value: text[start:i]})
		}
		if len(tokens) > 65536 {
			return nil, errors.New("apt token limit exceeded")
		}
	}
	return tokens, nil
}

func aptSettings(text string, settings map[string]string) error {
	tokens, err := aptTokens(text)
	if err != nil {
		return err
	}
	position := 0
	var parse func(string, int) error
	parse = func(prefix string, depth int) error {
		if depth > 32 {
			return errors.New("apt nesting limit exceeded")
		}
		for position < len(tokens) {
			key := tokens[position]
			position++
			if key.symbol == '}' {
				if depth == 0 {
					return errors.New("unmatched apt block")
				}
				return nil
			}
			if key.symbol != 0 || position >= len(tokens) {
				return errors.New("malformed apt setting")
			}
			next := tokens[position]
			position++
			full := strings.ToLower(key.value)
			if prefix != "" {
				full = prefix + "::" + full
			}
			if next.symbol == '{' {
				if key.quoted {
					return errors.New("quoted apt scope requires review")
				}
				if err := parse(full, depth+1); err != nil {
					return err
				}
				if position >= len(tokens) || tokens[position].symbol != ';' {
					return errors.New("apt block lacks terminator")
				}
				position++
				continue
			}
			if next.symbol == ';' && key.quoted && depth > 0 {
				continue
			} // Anonymous list member, not a named setting.
			if next.symbol != 0 || key.quoted || position >= len(tokens) || tokens[position].symbol != ';' {
				return errors.New("apt setting is outside reviewed grammar")
			}
			position++
			settings[full] = strings.ToLower(next.value)
		}
		if depth != 0 {
			return errors.New("unterminated apt scope")
		}
		return nil
	}
	return parse("", 0)
}

var aptPartName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// apt also loads *.conf parts from apt.conf.d (for example 20snapd.conf).
var aptConfName = regexp.MustCompile(`^[A-Za-z0-9_-]+(\.conf)?$`)

func aptAuthentication(system fs.FS) (string, string) {
	files := []string{}
	entries, err := nativeEntries(system, "etc/apt/apt.conf.d", false)
	if err != nil {
		return wire.Error, "cannot inspect apt authentication configuration directory"
	}
	for _, entry := range entries {
		if !aptConfName.MatchString(entry.Name()) {
			return wire.Error, "apt configuration directory contains a filename outside the reviewed load-order subset"
		}
		files = append(files, "etc/apt/apt.conf.d/"+entry.Name())
	}
	if _, err := nativeStat(system, "etc/apt/apt.conf"); err == nil {
		files = append(files, "etc/apt/apt.conf")
	} else if !isMissing(err) {
		return wire.Error, "cannot inspect main apt configuration"
	}
	if len(files) > 128 {
		return wire.Error, "apt configuration file bound exceeded"
	}
	settings := map[string]string{}
	totalBytes := 0
	for _, name := range files {
		data, err := nativeRead(system, name)
		if err != nil {
			return wire.Error, "cannot read apt configuration without following symlinks"
		}
		totalBytes += len(data)
		if totalBytes > 8*1024*1024 {
			return wire.Error, "apt configuration byte bound exceeded"
		}
		if err := aptSettings(data, settings); err != nil {
			return wire.Error, "apt configuration contains includes, resets or grammar outside the reviewed parser"
		}
		if len(settings) > 65536 {
			return wire.Error, "apt aggregate setting bound exceeded"
		}
	}
	for key, value := range settings {
		dangerous := false
		for _, suffix := range []string{"apt::get::allowunauthenticated", "acquire::allowinsecurerepositories", "acquire::allowdowngradetoinsecurerepositories", "acquire::allowweakrepositories"} {
			if key == suffix || strings.HasSuffix(key, "::"+suffix) {
				dangerous = true
			}
		}
		if !dangerous {
			continue
		}
		switch value {
		case "true", "yes", "1", "on":
			return wire.Fail, "apt file policy explicitly permits unauthenticated, insecure or weak repositories"
		case "false", "no", "0", "off":
		default:
			return wire.Error, "apt authentication option has an ambiguous boolean value"
		}
	}
	// Source-level trust bypasses can weaken authentication despite safe global defaults.
	sources := []string{}
	if _, err := nativeStat(system, "etc/apt/sources.list"); err == nil {
		sources = append(sources, "etc/apt/sources.list")
	} else if !isMissing(err) {
		return wire.Error, "cannot inspect apt source trust policy"
	}
	entries, err = nativeEntries(system, "etc/apt/sources.list.d", true)
	if err != nil {
		return wire.Error, "cannot inspect apt source trust directory"
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".list") || strings.HasSuffix(entry.Name(), ".sources") {
			sources = append(sources, "etc/apt/sources.list.d/"+entry.Name())
		}
	}
	if len(sources) > 128 {
		return wire.Error, "apt source trust file bound exceeded"
	}
	for _, name := range sources {
		data, err := nativeRead(system, name)
		if err != nil {
			return wire.Error, "cannot read apt source trust policy without following symlinks"
		}
		totalBytes += len(data)
		if totalBytes > 8*1024*1024 {
			return wire.Error, "apt aggregate policy byte bound exceeded"
		}
		for _, raw := range strings.Split(data, "\n") {
			line := strings.ToLower(uncomment(raw))
			if line == "" {
				continue
			}
			if strings.ContainsAny(line, "\\\x00") {
				return wire.Error, "continued or binary apt source trust policy requires review"
			}
			if strings.HasSuffix(name, ".sources") {
				key, value, ok := strings.Cut(line, ":")
				if !ok {
					if raw[0] == ' ' || raw[0] == '\t' {
						continue
					}
					return wire.Error, "malformed deb822 source trust policy"
				}
				if !oneOfPolicy(strings.TrimSpace(key), "trusted", "allow-insecure", "allow-weak", "allow-downgrade-to-insecure") {
					continue
				}
				switch strings.TrimSpace(value) {
				case "yes", "true", "1":
					return wire.Fail, "an apt source explicitly bypasses repository authentication"
				case "no", "false", "0":
				default:
					return wire.Error, "apt source trust value is outside reviewed boolean syntax"
				}
			} else {
				start, end := strings.IndexByte(line, '['), strings.IndexByte(line, ']')
				if start < 0 && end < 0 {
					continue
				}
				if start < 0 || end < start {
					return wire.Error, "malformed apt source options"
				}
				for _, option := range strings.Fields(line[start+1 : end]) {
					key, value, ok := strings.Cut(option, "=")
					if !oneOfPolicy(key, "trusted", "allow-insecure", "allow-weak", "allow-downgrade-to-insecure") {
						continue
					}
					if !ok {
						return wire.Error, "apt source trust option has no explicit value"
					}
					switch value {
					case "yes", "true", "1":
						return wire.Fail, "an apt source explicitly bypasses repository authentication"
					case "no", "false", "0":
					default:
						return wire.Error, "apt source trust option uses unsupported quoting or boolean syntax"
					}
				}
			}
		}
	}
	return wire.Pass, "reviewed apt configuration and source files do not enable authentication bypasses; environment and per-invocation overrides are outside this file-policy observation"
}

func oneOfPolicy(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

func sudoLogfile(system fs.FS) (string, string) {
	value := ""
	allowed, denied := true, true
	seen := map[string]bool{}
	totalBytes := 0
	var load func(string) error
	load = func(name string) error {
		if seen[name] || len(seen) >= 128 {
			return errors.New("recursive or oversized sudoers includes")
		}
		seen[name] = true
		data, err := nativeRead(system, name)
		if err != nil {
			return err
		}
		totalBytes += len(data)
		if totalBytes > 8*1024*1024 {
			return errors.New("sudoers aggregate byte bound exceeded")
		}
		for _, raw := range strings.Split(data, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" {
				continue
			}
			var include, argument string
			for _, directive := range []string{"#includedir", "@includedir", "#include", "@include"} {
				if strings.HasPrefix(line, directive+" ") || strings.HasPrefix(line, directive+"\t") {
					include = directive
					argument = strings.TrimSpace(strings.TrimPrefix(line, directive))
					break
				}
			}
			if include != "" {
				if strings.HasSuffix(include, "includedir") {
					if argument != "/etc/sudoers.d" {
						return errors.New("sudoers include directory is outside reviewed path")
					}
					entries, err := nativeEntries(system, "etc/sudoers.d", false)
					if err != nil {
						return err
					}
					for _, entry := range entries {
						if strings.Contains(entry.Name(), ".") || strings.HasSuffix(entry.Name(), "~") {
							continue
						}
						if !aptPartName.MatchString(entry.Name()) {
							return errors.New("unsupported sudoers filename")
						}
						if err := load("etc/sudoers.d/" + entry.Name()); err != nil {
							return err
						}
					}
				} else {
					name := strings.TrimPrefix(argument, "/")
					if !strings.HasPrefix(argument, "/") || path.Dir(name) != "etc/sudoers.d" || !fs.ValidPath(name) || strings.ContainsAny(argument, "%\"'\\ \t") {
						return errors.New("sudoers include is outside reviewed literal path")
					}
					if err := load(name); err != nil {
						return err
					}
				}
				continue
			}
			if strings.HasPrefix(line, "@") || strings.HasPrefix(line, "#include") {
				return errors.New("unrecognized sudoers include directive")
			}
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.ContainsAny(line, "\\\x00") {
				return errors.New("continued sudoers syntax requires review")
			}
			if !strings.HasPrefix(line, "Defaults") {
				continue
			}
			if len(line) == 8 || line[8] != ' ' && line[8] != '\t' {
				lower := strings.ToLower(line)
				if strings.Contains(lower, "logfile") || strings.Contains(lower, "log_allowed") || strings.Contains(lower, "log_denied") {
					return errors.New("scoped sudo logfile settings require host/user/command evaluation")
				}
				continue
			}
			options, err := splitSudoDefaults(strings.TrimSpace(line[8:]))
			if err != nil {
				return err
			}
			for _, option := range options {
				option = strings.TrimSpace(option)
				switch option {
				case "log_allowed":
					allowed = true
					continue
				case "!log_allowed":
					allowed = false
					continue
				case "log_denied":
					denied = true
					continue
				case "!log_denied":
					denied = false
					continue
				}
				if strings.Contains(option, "log_allowed") || strings.Contains(option, "log_denied") {
					return errors.New("unreviewed sudo logging boolean assignment")
				}
				if option == "!logfile" {
					value = ""
					continue
				}
				key, v, ok := strings.Cut(option, "=")
				if strings.TrimSpace(key) != "logfile" {
					if strings.Contains(strings.ToLower(option), "logfile") {
						return errors.New("unrecognized sudo logfile assignment")
					}
					continue
				}
				if !ok {
					return errors.New("sudo logfile has no path")
				}
				v = strings.TrimSpace(v)
				if strings.HasPrefix(v, "\"") {
					if len(v) < 2 || !strings.HasSuffix(v, "\"") {
						return errors.New("unclosed sudo logfile quote")
					}
					v = v[1 : len(v)-1]
				}
				if !strings.HasPrefix(v, "/") || strings.ContainsAny(v, "%$\"'\\ \t") {
					return errors.New("sudo logfile path has dynamic or unsupported syntax")
				}
				value = v
			}
		}
		return nil
	}
	if err := load("etc/sudoers"); err != nil {
		return wire.Error, "sudoers logging policy contains unavailable, scoped, recursive or unreviewed syntax"
	}
	return result(value == "/var/log/sudo.log" && allowed && denied, "reviewed global sudoers logfile and logging-disable directives inspected; expected /var/log/sudo.log and no disabled allowed/denied logging; no log contents opened")
}

func splitSudoDefaults(line string) ([]string, error) {
	quoted := false
	start := 0
	parts := []string{}
	for i, c := range line {
		if c == '"' {
			quoted = !quoted
			continue
		}
		if c == '#' && !quoted {
			line = line[:i]
			break
		}
		if c == ',' && !quoted {
			parts = append(parts, line[start:i])
			start = i + 1
		}
	}
	if quoted {
		return nil, errors.New("unbalanced sudoers quoting")
	}
	parts = append(parts, line[start:])
	return parts, nil
}

func pamHistory(system fs.FS) (string, string) {
	data, err := nativeRead(system, "etc/pam.d/common-password")
	if err != nil {
		return wire.Error, "cannot inspect common-password PAM policy without following symlinks"
	}
	if _, err := nativeStat(system, "etc/security/pwhistory.conf"); err == nil {
		policy, err := nativeRead(system, "etc/security/pwhistory.conf")
		if err != nil {
			return wire.Error, "cannot inspect password-history policy configuration"
		}
		for _, raw := range strings.Split(policy, "\n") {
			line := uncomment(raw)
			if line == "" {
				continue
			}
			if oneOfPolicy(line, "debug", "enforce_for_root") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				return wire.Error, "password-history configuration uses unreviewed syntax"
			}
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			switch key {
			case "file":
				if value != "/etc/security/opasswd" {
					return wire.Error, "alternate password-history storage requires manual evaluation; its contents are not read"
				}
			case "remember", "retry":
				if n, err := strconv.Atoi(value); err != nil || n < 0 {
					return wire.Error, "invalid password-history configuration value"
				}
			default:
				return wire.Error, "unreviewed password-history configuration directive"
			}
		}
	} else if !isMissing(err) {
		return wire.Error, "cannot safely inspect password-history configuration"
	}
	historySeen := false
	remember := 0
	for _, raw := range strings.Split(data, "\n") {
		line := uncomment(raw)
		if line == "" {
			continue
		}
		if strings.ContainsAny(line, "\\\"'\x00") || strings.HasPrefix(line, "@") {
			return wire.Error, "PAM includes, continuations or complex quoting require full stack evaluation"
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "password" {
			return wire.Error, "PAM file contains syntax outside the reviewed password-stack subset"
		}
		control := fields[1]
		moduleIndex := 2
		if strings.HasPrefix(control, "[") {
			end := strings.Index(line, "]")
			if end < 0 {
				return wire.Error, "unterminated PAM control expression"
			}
			start := strings.Index(line, "[")
			control = strings.Join(strings.Fields(line[start:end+1]), " ")
			if !historySeen || control != "[success=1 default=ignore]" {
				return wire.Error, "PAM control jumps may bypass or reset password-history enforcement"
			}
			moduleIndex = 2
			for moduleIndex < len(fields) && !strings.HasSuffix(fields[moduleIndex-1], "]") {
				moduleIndex++
			}
		}
		if moduleIndex >= len(fields) {
			return wire.Error, "PAM control has no module"
		}
		module := fields[moduleIndex]
		if !oneOfPolicy(module, "pam_pwquality.so", "pam_pwhistory.so", "pam_unix.so", "pam_deny.so", "pam_permit.so") {
			return wire.Error, "unreviewed PAM module or external module path requires manual evaluation"
		}
		if !oneOfPolicy(control, "required", "requisite", "optional", "sufficient", "[success=1 default=ignore]") {
			return wire.Error, "unsupported PAM control action"
		}
		if !historySeen && module != "pam_pwquality.so" && module != "pam_pwhistory.so" {
			return wire.Error, "a module before history may change the password or bypass history"
		}
		if !historySeen && module == "pam_pwquality.so" && !oneOfPolicy(control, "required", "requisite") {
			return wire.Error, "password-quality control before history may bypass it"
		}
		if strings.HasPrefix(control, "[") && module != "pam_unix.so" {
			return wire.Error, "PAM jump expression is not attached to the reviewed unix module"
		}
		if historySeen && module == "pam_pwquality.so" {
			return wire.Error, "a later quality module may replace the candidate checked by history"
		}
		if module == "pam_unix.so" {
			bound := false
			for _, option := range fields[moduleIndex+1:] {
				if strings.HasPrefix(option, "remember=") {
					return wire.Error, "unix-module history options may overwrite the dedicated history store"
				}
				if option == "use_authtok" {
					bound = true
				}
			}
			if !bound {
				return wire.Error, "password-writing module is not bound to the candidate checked by history"
			}
		}
		if module != "pam_pwhistory.so" {
			continue
		}
		if historySeen || !oneOfPolicy(control, "required", "requisite") {
			return wire.Error, "history module is duplicated or not mandatory"
		}
		found, bound := false, false
		for _, option := range fields[moduleIndex+1:] {
			if option == "use_authtok" {
				bound = true
				continue
			}
			if oneOfPolicy(option, "debug", "enforce_for_root") {
				continue
			}
			if strings.HasPrefix(option, "retry=") {
				if n, err := strconv.Atoi(strings.TrimPrefix(option, "retry=")); err != nil || n < 1 || n > 1000 {
					return wire.Error, "invalid password-history retry value"
				}
				continue
			}
			if strings.HasPrefix(option, "remember=") {
				if found {
					return wire.Error, "duplicate password-history length option"
				}
				found = true
				remember, err = strconv.Atoi(strings.TrimPrefix(option, "remember="))
				if err != nil || remember < 0 || remember > 1000 {
					return wire.Error, "invalid password-history length"
				}
				continue
			}
			return wire.Error, "alternate storage/configuration or unreviewed password-history option requires manual evaluation"
		}
		if !found {
			return wire.Error, "password history length is implicit or external"
		}
		if !bound {
			return wire.Error, "history module is not explicitly bound to the shared password candidate"
		}
		historySeen = true
	}
	if !historySeen {
		return wire.Fail, "no mandatory explicit password-history module is configured in common-password"
	}
	return result(remember >= 5, "reviewed mandatory common-password history policy requires at least five prior passwords; other PAM service entry points and stored history contents are not inspected")
}
