package report

import (
	"context"
	"github.com/Wearden/proto/wire"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func sample() wire.Report {
	now := time.Now().UTC()
	return wire.Report{Version: "1", ReportID: "r1", AgentID: "a1", BenchmarkID: "ubuntu", RulesetVersion: "1", StartedAt: now, FinishedAt: now, Findings: []wire.Finding{{RuleID: "LNX-FS-001", Status: wire.Pass, Severity: "low"}}}
}
func TestSubmit(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
		code        int
		ok          bool
	}{
		{"accepted", `{"report_id":"r1","accepted":true}`, 200, true},
		{"wrong receipt", `{"report_id":"another","accepted":true}`, 200, false},
		{"rejected", `{"report_id":"r1","accepted":false}`, 200, false},
		{"auth rejected", `{}`, 401, false},
		{"redirect", "", 302, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer lab-test-token" || r.URL.Path != "/api/agent/v1/reports" || r.Method != "POST" {
					t.Error("bad request")
				}
				w.WriteHeader(tc.code)
				w.Write([]byte(tc.reply))
			}))
			defer s.Close()
			c, err := NewClient(s.URL, "lab-test-token")
			if err != nil {
				t.Fatal(err)
			}
			err = c.Submit(context.Background(), sample())
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
func TestTransportGuard(t *testing.T) {
	for _, base := range []string{"http://example.com", "https://user:password@example.com", "https://example.com/?x=1", "https://example.com/path"} {
		if _, err := NewClient(base, "token"); err == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
}
