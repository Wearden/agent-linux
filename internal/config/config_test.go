package config

import (
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	good := `{"version":"1","benchmark_id":"ubuntu-24.04-native-filesystem","ruleset_version":"1","rules":[{"id":"LNX-FS-001","kind":"kernel_module","target":"cramfs","severity":"low"}]}`
	if _, err := Load(strings.NewReader(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(good, "cramfs", "../../etc/passwd", 1), strings.Replace(good, "kernel_module", "command", 1), good + "{}", strings.Replace(good, `"severity":"low"`, `"severity":"low","command":"anything"`, 1), strings.Replace(good, "LNX-FS-001", "LNX-FS-999", 1)} {
		if _, err := Load(strings.NewReader(bad)); err == nil {
			t.Fatal("accepted unsafe rules")
		}
	}
}
