package checks

import (
	"github.com/Wearden/proto/wire"
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestKernelModule(t *testing.T) {
	rule := Rule{ID: "LNX-FS-001", Kind: "kernel_module", Target: "cramfs", Severity: "low"}
	cases := []struct {
		name, config, modules string
		want                  string
	}{
		{"blocked", "install cramfs /bin/false\nblacklist cramfs\n", "", wire.Pass},
		{"usr true and comments", "install cramfs /usr/bin/true # disabled\nblacklist cramfs # blocked\n", "", wire.Pass},
		{"missing blacklist", "install cramfs /bin/false\n", "", wire.Fail},
		{"loaded", "install cramfs /bin/false\nblacklist cramfs\n", "cramfs 123 0 - Live 0x0\n", wire.Fail},
		{"override enables", "install cramfs /bin/false\nblacklist cramfs\ninstall cramfs /sbin/modprobe cramfs\n", "", wire.Error},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := fstest.MapFS{"tmp": {Mode: fs.ModeDir}, "sys/module": {Mode: fs.ModeDir}, "proc/modules": {Data: []byte(c.modules)}, "etc/modprobe.d/security.conf": {Data: []byte(c.config)}}
			got := Run(fs, []Rule{rule})
			if got[0].Status != c.want {
				t.Fatalf("got %+v want %s", got, c.want)
			}
		})
	}
}
func TestModuleNameNormalization(t *testing.T) {
	fs := fstest.MapFS{"tmp": {Mode: fs.ModeDir}, "sys/module": {Mode: fs.ModeDir}, "proc/modules": {Data: []byte("")}, "etc/modprobe.d/security.conf": {Data: []byte("install usb_storage /bin/false\nblacklist usb-storage\n")}}
	got := Run(fs, []Rule{{ID: "LNX-FS-008", Kind: "kernel_module", Target: "usb-storage", Severity: "medium"}})
	if got[0].Status != wire.Pass {
		t.Fatal(got)
	}
}
func TestConfigBasenamePriority(t *testing.T) {
	fs := fstest.MapFS{"tmp": {Mode: fs.ModeDir}, "sys/module": {Mode: fs.ModeDir}, "proc/modules": {}, "etc/modprobe.d/security.conf": {Data: []byte("install cramfs /bin/false\nblacklist cramfs\n")}, "usr/lib/modprobe.d/security.conf": {Data: []byte("install cramfs /sbin/modprobe cramfs\n")}}
	got := Run(fs, []Rule{{ID: "LNX-FS-001", Kind: "kernel_module", Target: "cramfs", Severity: "low"}})
	if got[0].Status != wire.Pass {
		t.Fatal(got)
	}
}
func TestMissingEvidenceIsError(t *testing.T) {
	got := Run(fstest.MapFS{"tmp": {Mode: fs.ModeDir}, "sys/module": {Mode: fs.ModeDir}}, []Rule{{ID: "LNX-FS-001", Kind: "kernel_module", Target: "cramfs", Severity: "low"}})
	if got[0].Status != wire.Error {
		t.Fatal(got)
	}
}
func TestMounts(t *testing.T) {
	rule := Rule{ID: "LNX-FS-009", Kind: "mount_options", Target: "/tmp", Severity: "medium"}
	for _, c := range []struct {
		name, info string
		want       string
	}{
		{"secure", "12 1 0:1 / / rw - ext4 /dev/sda rw\n14 12 0:2 / /tmp rw,nodev,nosuid,noexec - tmpfs tmpfs rw\n", wire.Pass},
		{"missing flag", "14 1 0:2 / /tmp rw,nodev,nosuid - tmpfs tmpfs rw\n", wire.Fail},
		{"ancestor", "12 1 0:1 / / rw - ext4 /dev/sda rw\n", wire.Fail},
		{"ambiguous", "14 1 0:2 / /tmp rw,nodev,nosuid,noexec - tmpfs tmpfs rw\n15 1 0:3 / /tmp rw - tmpfs tmpfs rw\n", wire.Error},
		{"malformed", "bad data", wire.Error},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := Run(fstest.MapFS{"tmp": {Mode: fs.ModeDir}, "sys/module": {Mode: fs.ModeDir}, "proc/self/mountinfo": {Data: []byte(c.info)}}, []Rule{rule})
			if got[0].Status != c.want {
				t.Fatalf("%+v", got)
			}
		})
	}
}
