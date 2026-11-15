package checks

import (
	"github.com/Wearden/proto/wire"
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestUntrustedModuleEvidence(t *testing.T) {
	rule := Rule{ID: "LNX-FS-001", Kind: "kernel_module", Target: "cramfs", Severity: "low"}
	for _, c := range []struct {
		name, config string
		sysfs        bool
	}{
		{"first unsafe install", "install cramfs /sbin/modprobe cramfs\ninstall cramfs /bin/false\nblacklist cramfs\n", true},
		{"wildcard install", "install c* /sbin/modprobe cramfs\ninstall cramfs /bin/false\nblacklist cramfs\n", true},
		{"missing sysfs", "install cramfs /bin/false\nblacklist cramfs\n", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			system := fstest.MapFS{"proc/modules": {}, "etc/modprobe.d/security.conf": {Data: []byte(c.config)}}
			if c.sysfs {
				system["sys/module"] = &fstest.MapFile{Mode: fs.ModeDir}
			}
			got := Run(system, []Rule{rule})
			if got[0].Status != wire.Error {
				t.Fatalf("got %+v expected error", got)
			}
		})
	}
}
