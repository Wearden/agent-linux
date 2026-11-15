package checks

import (
	"github.com/Wearden/proto/wire"
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestSoftDependencyCannotPass(t *testing.T) {
	for _, directive := range []string{"softdep cramfs pre: other", "softdep c* pre: other"} {
		system := fstest.MapFS{"sys/module": {Mode: fs.ModeDir}, "proc/modules": {}, "etc/modprobe.d/security.conf": {Data: []byte("install cramfs /bin/false\nblacklist cramfs\n" + directive + "\n")}}
		got := Run(system, []Rule{{ID: "LNX-FS-001", Kind: "kernel_module", Target: "cramfs", Severity: "low"}})
		if got[0].Status != wire.Error {
			t.Fatal(got)
		}
	}
}
func TestMountTargetMustExistAndNotBeSymlink(t *testing.T) {
	for _, target := range []*fstest.MapFile{nil, {Mode: fs.ModeSymlink, Data: []byte("other")}} {
		system := fstest.MapFS{"proc/self/mountinfo": {Data: []byte("1 0 0:1 / / rw,nodev,nosuid,noexec - tmpfs tmpfs rw\n")}}
		if target != nil {
			system["tmp"] = target
		}
		got := Run(system, []Rule{{ID: "LNX-FS-009", Kind: "mount_options", Target: "/tmp", Severity: "medium"}})
		if got[0].Status != wire.Error {
			t.Fatal(got)
		}
	}
}
