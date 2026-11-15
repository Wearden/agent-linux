package main

import (
	"context"
	"encoding/json"
	"github.com/Wearden/agent-linux/internal/checks"
	"github.com/Wearden/agent-linux/internal/config"
	"github.com/Wearden/agent-linux/internal/report"
	"github.com/Wearden/proto/wire"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestNativeScanToAuthenticatedReport(t *testing.T) {
	system := fstest.MapFS{"sys/module": {Mode: fs.ModeDir}, "proc/modules": {}, "etc/modprobe.d/security.conf": {Data: []byte("install cramfs /bin/false\nblacklist cramfs\n")}}
	rules := config.Ruleset{Version: "1", BenchmarkID: "ubuntu-24.04-native-filesystem", RulesetVersion: "1", Rules: []checks.Rule{{ID: "LNX-FS-001", Kind: "kernel_module", Target: "cramfs", Severity: "low"}}}
	scanReport, err := scan(rules, system, "fixture-agent")
	if err != nil {
		t.Fatal(err)
	}
	var received wire.Report
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			w.WriteHeader(401)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if err := received.Validate(); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(wire.Receipt{ReportID: received.ReportID, Accepted: true})
	}))
	defer server.Close()
	client, err := report.NewClient(server.URL, "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Submit(context.Background(), scanReport); err != nil {
		t.Fatal(err)
	}
	if len(received.Findings) != 1 || received.Findings[0].Status != wire.Pass || received.AgentID != "fixture-agent" {
		t.Fatal("invalid received report")
	}
}
