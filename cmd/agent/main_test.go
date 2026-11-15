package main

import (
	"github.com/Wearden/agent-linux/internal/checks"
	"github.com/Wearden/agent-linux/internal/config"
	"github.com/Wearden/proto/wire"
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestScanReport(t *testing.T) {
	rules := config.Ruleset{Version: "1", BenchmarkID: "ubuntu-24.04-native-filesystem", RulesetVersion: "1", Rules: []checks.Rule{{ID: "LNX-FS-001", Kind: "kernel_module", Target: "cramfs", Severity: "low"}}}
	fs := fstest.MapFS{"sys/module": {Mode: fs.ModeDir}, "proc/modules": {}, "etc/modprobe.d/security.conf": {Data: []byte("install cramfs /bin/false\nblacklist cramfs\n")}}
	r, err := scan(rules, fs, "fixture-agent")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if r.Findings[0].Status != wire.Pass {
		t.Fatal(r.Findings)
	}
	if _, err := scan(rules, fs, ""); err == nil {
		t.Fatal("empty identity accepted")
	}
}
