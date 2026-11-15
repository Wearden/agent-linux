package checks

import (
	"errors"
	"io/fs"
	"strings"
)

// RequireUbuntu2404 checks distribution metadata, not the kernel or host outside
// the agent's filesystem namespace. Only the standard os-release link is allowed.
func RequireUbuntu2404(system fs.FS) error {
	if _, err := nativeStat(system, "etc"); err != nil {
		return errors.New("cannot safely inspect OS metadata directory")
	}
	links, ok := system.(fs.ReadLinkFS)
	if !ok {
		return errors.New("OS metadata filesystem cannot inspect symlinks")
	}
	name := "etc/os-release"
	info, err := links.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		name = "usr/lib/os-release"
	} else if err != nil {
		return errors.New("cannot inspect OS release metadata")
	} else if info.Mode()&fs.ModeSymlink != 0 {
		target, err := links.ReadLink(name)
		if err != nil || (target != "../usr/lib/os-release" && target != "/usr/lib/os-release") {
			return errors.New("OS release link is outside the standard metadata location")
		}
		name = "usr/lib/os-release"
	}
	data, err := nativeRead(system, name)
	if err != nil {
		return errors.New("OS release metadata is unavailable or unsafe")
	}
	values := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || (key != "ID" && key != "VERSION_ID") {
			continue
		}
		if _, exists := values[key]; exists {
			return errors.New("duplicate OS release identity field")
		}
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		if value == "" || strings.ContainsAny(value, " \t\r$`\\\"'") {
			return errors.New("OS release identity is not an explicit literal")
		}
		values[key] = value
	}
	if values["ID"] != "ubuntu" || values["VERSION_ID"] != "24.04" {
		return errors.New("assigned Ubuntu 24.04 native baseline is not applicable to this distribution release")
	}
	return nil
}
