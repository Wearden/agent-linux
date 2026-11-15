package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Wearden/agent-linux/internal/checks"
	"github.com/Wearden/agent-linux/internal/config"
	"github.com/Wearden/agent-linux/internal/report"
	"github.com/Wearden/proto/wire"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func scan(r config.Ruleset, system fs.FS, agentID string) (wire.Report, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return wire.Report{}, err
	}
	started := time.Now().UTC()
	findings := checks.Run(system, r.Rules)
	result := wire.Report{Version: wire.Version, ReportID: hex.EncodeToString(id), AgentID: agentID, BenchmarkID: r.BenchmarkID, RulesetVersion: r.RulesetVersion, StartedAt: started, FinishedAt: time.Now().UTC(), Findings: findings}
	return result, result.Validate()
}
func run() error {
	rulesPath := flag.String("rules", "", "path to reviewed native JSON ruleset (required)")
	agentID := flag.String("agent-id", "", "enrolled agent identity (required)")
	coreURL := flag.String("core-url", "", "submit report to this core origin; omit for stdout only")
	expected := flag.String("rules-sha256", "", "expected SHA-256 of assigned ruleset; required for submission")
	daemon := flag.Bool("daemon", false, "enroll and run the scheduled agent with durable report delivery")
	allowRemediation := flag.Bool("allow-remediation", false, "allow confirmed locally reviewed native apply/rollback tasks in daemon mode")
	stateDir := flag.String("state-dir", defaultStateDir(), "private agent state and report spool directory")
	recoverTask := flag.String("recover-task", "", "local operator: restore one task backup while the daemon is stopped")
	watchdogDir := flag.String("watchdog-dir", "", "internal private recovery scope")
	watchdogTask := flag.String("watchdog-task", "", "internal recovery task identity")
	flag.Parse()
	if runtime.GOOS != "linux" {
		return errors.New("native scanning requires Linux; fixtures can be tested on other systems")
	}
	if *recoverTask != "" {
		return recoverManualTask(*stateDir, *recoverTask)
	}
	if *watchdogDir != "" || *watchdogTask != "" {
		if *watchdogDir == "" || *watchdogTask == "" {
			return errors.New("both internal watchdog parameters are required")
		}
		return runWatchdog(*watchdogDir, *watchdogTask)
	}
	if *daemon {
		if *coreURL == "" {
			return errors.New("-daemon requires -core-url")
		}
		if *rulesPath != "" || *expected != "" {
			return errors.New("daemon rules and digest are assigned by core")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return runDaemon(ctx, *stateDir, *coreURL, *agentID, *allowRemediation)
	}
	if *rulesPath == "" || *agentID == "" {
		return errors.New("-rules and -agent-id are required")
	}
	file, err := os.Open(*rulesPath)
	if err != nil {
		return errors.New("cannot open ruleset")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	if err != nil {
		return errors.New("cannot read ruleset")
	}
	if len(data) > 1024*1024 {
		return errors.New("ruleset exceeds 1 MiB")
	}
	sum := sha256.Sum256(data)
	actual := hex.EncodeToString(sum[:])
	if *expected != "" && *expected != actual {
		return errors.New("ruleset SHA-256 mismatch")
	}
	var client *report.Client
	if *coreURL != "" {
		if *expected == "" {
			return errors.New("submission requires -rules-sha256 from core configuration")
		}
		client, err = report.NewClient(*coreURL, os.Getenv("WEARDEN_AGENT_TOKEN"))
		if err != nil {
			return err
		}
	}
	rules, err := config.Load(bytes.NewReader(data))
	if err != nil {
		return err
	}
	if err := checks.RequireUbuntuBenchmark(os.DirFS("/"), rules.BenchmarkID); err != nil {
		return err
	}
	result, err := scan(rules, os.DirFS("/"), *agentID)
	if err != nil {
		return err
	}
	// Write the report before sending it so a failed upload can be captured and retried by the caller.
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		return err
	}
	if client != nil {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := client.Submit(ctx, result); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "report accepted by core")
	}
	scores := wire.Score(result.Findings)
	summary, _ := json.Marshal(scores)
	fmt.Fprintln(os.Stderr, strings.TrimSpace(string(summary)))
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agent:", err)
		os.Exit(1)
	}
}
