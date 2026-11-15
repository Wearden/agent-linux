package config

import (
	"os"
	"testing"
)

func TestReviewedManifest(t *testing.T) {
	path := os.Getenv("WEARDEN_TEST_RULESET_PATH")
	if path == "" {
		t.Skip("set WEARDEN_TEST_RULESET_PATH for sibling ruleset integration")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rules, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules.Rules) != 10 {
		t.Fatal("expected all ten reviewed filesystem controls")
	}
}
