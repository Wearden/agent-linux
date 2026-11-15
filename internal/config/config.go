package config

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Wearden/agent-linux/internal/checks"
	"io"
)

//go:embed catalog.json
var nativeCatalog []byte

//go:embed catalog-2204.json
var nativeCatalog2204 []byte

// NativeRule resolves metadata locally; task payloads may select IDs, never paths.
func NativeRule(id string) (checks.Rule, bool) {
	// The shared88 control definitions are identical across both releases.
	// Ubuntu22 adds read-only audit IDs; mutation paths remain fixed by ID.
	for _, raw := range [][]byte{nativeCatalog, nativeCatalog2204} {
		var catalog Ruleset
		if json.Unmarshal(raw, &catalog) != nil {
			return checks.Rule{}, false
		}
		for _, rule := range catalog.Rules {
			if rule.ID == id {
				return rule, true
			}
		}
	}
	return checks.Rule{}, false
}

type Ruleset struct {
	Version        string        `json:"version"`
	BenchmarkID    string        `json:"benchmark_id"`
	RulesetVersion string        `json:"ruleset_version"`
	Rules          []checks.Rule `json:"rules"`
}

var approved = map[string]checks.Rule{
	"LNX-FS-001": {Kind: "kernel_module", Target: "cramfs", Severity: "low"},
	"LNX-FS-002": {Kind: "kernel_module", Target: "freevxfs", Severity: "low"},
	"LNX-FS-003": {Kind: "kernel_module", Target: "jffs2", Severity: "low"},
	"LNX-FS-004": {Kind: "kernel_module", Target: "hfs", Severity: "low"},
	"LNX-FS-005": {Kind: "kernel_module", Target: "hfsplus", Severity: "low"},
	"LNX-FS-006": {Kind: "mount_options", Target: "/var/tmp", Severity: "medium"},
	"LNX-FS-007": {Kind: "kernel_module", Target: "udf", Severity: "low"},
	"LNX-FS-008": {Kind: "kernel_module", Target: "usb-storage", Severity: "medium"},
	"LNX-FS-009": {Kind: "mount_options", Target: "/tmp", Severity: "medium"},
	"LNX-FS-010": {Kind: "mount_options", Target: "/dev/shm", Severity: "medium"},
}

func Load(reader io.Reader) (Ruleset, error) {
	var r Ruleset
	// Read one byte past the limit so oversized manifests fail instead of truncating silently.
	data, err := io.ReadAll(io.LimitReader(reader, 1024*1024+1))
	if err != nil {
		return r, err
	}
	if len(data) > 1024*1024 {
		return r, errors.New("ruleset exceeds 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("invalid ruleset: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return r, errors.New("trailing JSON content")
	}
	allowed := approved
	if r.Version == "1" && (r.BenchmarkID == "ubuntu-24.04-native" || r.BenchmarkID == "ubuntu-22.04-native") {
		var catalog Ruleset
		raw := nativeCatalog
		if r.BenchmarkID == "ubuntu-22.04-native" {
			raw = nativeCatalog2204
		}
		if err := json.Unmarshal(raw, &catalog); err != nil {
			return r, errors.New("invalid embedded native catalog")
		}
		if r.RulesetVersion != catalog.RulesetVersion {
			return r, errors.New("native ruleset version differs from embedded catalog")
		}
		allowed = make(map[string]checks.Rule, len(catalog.Rules))
		for _, rule := range catalog.Rules {
			allowed[rule.ID] = rule
		}
	} else if r.Version != "1" || r.BenchmarkID != "ubuntu-24.04-native-filesystem" || r.RulesetVersion != "1" {
		return r, errors.New("unsupported native ruleset version")
	}
	if len(r.Rules) == 0 || len(r.Rules) > len(allowed) {
		return r, errors.New("invalid native rule count")
	}
	seen := map[string]bool{}
	for _, rule := range r.Rules {
		a, ok := allowed[rule.ID]
		if !ok || seen[rule.ID] || a.Kind != rule.Kind || a.Target != rule.Target || a.Severity != rule.Severity {
			return r, fmt.Errorf("unsupported, duplicate or changed native rule: %s", rule.ID)
		}
		seen[rule.ID] = true
	}
	return r, nil
}
