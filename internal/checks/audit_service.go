package checks

import (
	"io/fs"
	"path"
	"strings"

	"github.com/Wearden/proto/wire"
)

// The legacy audit checks enablement only. Do not infer running service state.
func auditdEnabled(system fs.FS) (string, string) {
	links, ok := system.(fs.ReadLinkFS)
	if !ok {
		return wire.Error, "filesystem cannot inspect auditd enablement links"
	}
	const unit = "auditd.service"
	// Generated, transient and control units need manager evaluation.
	for _, base := range []string{"etc/systemd/system.control", "run/systemd/system.control", "run/systemd/transient", "run/systemd/generator.early", "run/systemd/generator", "run/systemd/generator.late", "etc/systemd/system.attached", "run/systemd/system.attached"} {
		if _, err := nativeStat(system, base); isMissing(err) {
			continue
		} else if err != nil {
			return wire.Error, "cannot safely inspect alternate systemd unit directory"
		}
		if _, err := links.Lstat(base + "/" + unit); !isMissing(err) {
			return wire.Error, "alternate auditd unit requires systemd manager evaluation"
		}
	}
	selected := ""
	for _, base := range []string{"etc/systemd/system", "run/systemd/system", "usr/local/lib/systemd/system", "usr/lib/systemd/system"} {
		if _, err := nativeStat(system, base); isMissing(err) {
			continue
		} else if err != nil {
			return wire.Error, "cannot safely inspect auditd unit directory"
		}
		name := base + "/" + unit
		info, err := links.Lstat(name)
		if isMissing(err) {
			continue
		}
		if err != nil {
			return wire.Error, "cannot inspect auditd unit"
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			target, err := links.ReadLink(name)
			if err == nil && target == "/dev/null" {
				return wire.Fail, "auditd unit is masked"
			}
			return wire.Error, "auditd alias or linked unit requires systemd manager evaluation"
		}
		if !info.Mode().IsRegular() {
			return wire.Error, "auditd unit is not a regular file"
		}
		selected = "/" + name
		break
	}
	if selected == "" {
		return wire.Error, "auditd unit absent from reviewed unit paths; unmerged /lib layouts require review"
	}
	entries, err := nativeEntries(system, "etc/systemd/system", true)
	if err != nil {
		return wire.Error, "cannot inspect persistent auditd enablement"
	}
	found := false
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".wants") && !strings.HasSuffix(entry.Name(), ".requires") {
			continue
		}
		base := "etc/systemd/system/" + entry.Name()
		if _, err := nativeEntries(system, base, false); err != nil {
			return wire.Error, "cannot safely inspect persistent unit dependency directory"
		}
		name := base + "/" + unit
		info, err := links.Lstat(name)
		if isMissing(err) {
			continue
		}
		if err != nil || info.Mode()&fs.ModeSymlink == 0 {
			return wire.Error, "auditd dependency is inaccessible or not a symlink"
		}
		target, err := links.ReadLink(name)
		if err != nil || target == "" {
			return wire.Error, "cannot read auditd enablement link"
		}
		if !path.IsAbs(target) {
			target = path.Join("/"+base, target)
		}
		target = path.Clean(target)
		if strings.HasPrefix(target, "/lib/") {
			alias, err := links.ReadLink("lib")
			if err != nil || (alias != "usr/lib" && alias != "/usr/lib") {
				return wire.Error, "auditd enablement uses an unreviewed lib alias"
			}
			target = "/usr" + target
		}
		if target != selected {
			return wire.Error, "auditd enablement link differs from the selected unit"
		}
		found = true
	}
	return result(found, "persistent auditd enablement link inspected; running state and event delivery are not attested")
}
