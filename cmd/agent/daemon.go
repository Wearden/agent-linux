package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Wearden/agent-linux/internal/checks"
	"github.com/Wearden/agent-linux/internal/config"
	"github.com/Wearden/agent-linux/internal/report"
	"github.com/Wearden/proto/wire"
)

const maxSpoolFiles = 100
const maxSpoolBytes = 64 * 1024 * 1024
const maxReportBytes = 8 * 1024 * 1024

var safeIdentity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type agentState struct {
	Version    string    `json:"version"`
	CoreURL    string    `json:"core_url"`
	AgentID    string    `json:"agent_id"`
	AgentToken string    `json:"agent_token"`
	NextScan   time.Time `json:"next_scan"`
}

func defaultStateDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/wearden"
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "./wearden-state"
	}
	return filepath.Join(base, "wearden")
}

func decodeJSON(data []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return errors.New("invalid JSON data")
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("invalid trailing JSON data")
	}
	return nil
}

func privateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state path must be a real directory")
	}
	return os.Chmod(path, 0700)
}

func readPrivate(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state file must be regular with private permissions")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("state file exceeds size limit")
	}
	return data, nil
}

// Rename and directory fsync ensure acknowledged identity/report writes survive a restart.
func atomicJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func loadIdentity(ctx context.Context, dir, coreURL, agentID string) (agentState, error) {
	path := filepath.Join(dir, "identity.json")
	var state agentState
	data, err := readPrivate(path, 65536)
	if err == nil {
		if err := decodeJSON(data, &state); err != nil {
			return state, err
		}
		if state.Version != wire.Version || state.CoreURL != coreURL || !safeIdentity.MatchString(state.AgentID) {
			return state, errors.New("stored identity does not match this core or version")
		}
		if agentID != "" && agentID != state.AgentID {
			return state, errors.New("-agent-id conflicts with stored identity")
		}
		if _, err := report.NewClient(coreURL, state.AgentToken); err != nil {
			return state, err
		}
		return state, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return state, err
	}
	if err := checks.RequireSupportedUbuntu(os.DirFS("/")); err != nil {
		return state, err
	}
	state = agentState{Version: wire.Version, CoreURL: coreURL}
	if token := os.Getenv("WEARDEN_AGENT_TOKEN"); token != "" {
		if !safeIdentity.MatchString(agentID) {
			return state, errors.New("existing agent token requires valid -agent-id")
		}
		if _, err := report.NewClient(coreURL, token); err != nil {
			return state, err
		}
		state.AgentID, state.AgentToken = agentID, token
	} else {
		if agentID != "" {
			return state, errors.New("-agent-id requires WEARDEN_AGENT_TOKEN on first start")
		}
		client, err := report.NewClient(coreURL, os.Getenv("WEARDEN_ENROLLMENT_TOKEN"))
		if err != nil {
			return state, errors.New("first start requires WEARDEN_ENROLLMENT_TOKEN or an existing agent token and identity")
		}

		var pending struct {
			CoreURL string          `json:"core_url"`
			Request wire.Enrollment `json:"request"`
		}
		pendingPath := filepath.Join(dir, "enrollment-request.json")
		requestBytes, e := readPrivate(pendingPath, 65536)
		if e == nil {
			if e = decodeJSON(requestBytes, &pending); e != nil {
				return state, e
			}
			if pending.CoreURL != coreURL || pending.Request.Version != wire.Version || pending.Request.OS != "linux" || len(pending.Request.RequestID) != 32 {
				return state, errors.New("stored enrollment request does not match this core")
			}
		} else if errors.Is(e, os.ErrNotExist) {
			hostname, e := os.Hostname()
			if e != nil {
				return state, e
			}
			nonce := make([]byte, 16)
			if _, e = rand.Read(nonce); e != nil {
				return state, e
			}
			pending.CoreURL = coreURL
			pending.Request = wire.Enrollment{RequestID: hex.EncodeToString(nonce), Version: wire.Version, Hostname: hostname, OS: "linux", AgentVersion: "1"}
			if e = atomicJSON(pendingPath, pending); e != nil {
				return state, e
			}
		} else {
			return state, e
		}
		data, err := client.Request(ctx, http.MethodPost, "enroll", pending.Request, http.StatusCreated, 65536)
		if err != nil {
			return state, err
		}
		var enrolled wire.EnrollmentResponse
		if err := decodeJSON(data, &enrolled); err != nil {
			return state, err
		}
		if !safeIdentity.MatchString(enrolled.AgentID) {
			return state, errors.New("core returned invalid agent identity")
		}
		if _, err := report.NewClient(coreURL, enrolled.AgentToken); err != nil {
			return state, err
		}
		state.AgentID, state.AgentToken = enrolled.AgentID, enrolled.AgentToken
	}
	if err := atomicJSON(path, state); err != nil {
		return state, fmt.Errorf("cannot persist enrollment: %w", err)
	}
	return state, nil
}

func assignedConfig(ctx context.Context, client *report.Client) (wire.Config, error) {
	var assignment wire.Config
	data, err := client.Request(ctx, http.MethodGet, "config", nil, http.StatusOK, 65536)
	if err != nil {
		return assignment, err
	}
	if err := decodeJSON(data, &assignment); err != nil {
		return assignment, err
	}
	digest, err := hex.DecodeString(assignment.RulesetSHA256)
	if err != nil || len(digest) != sha256.Size || assignment.Version != wire.Version || assignment.IntervalSeconds < 60 || assignment.IntervalSeconds > 604800 || (assignment.ScanID != "" && !safeIdentity.MatchString(assignment.ScanID)) {
		return assignment, errors.New("invalid assigned configuration")
	}
	return assignment, nil
}

func assignedRules(ctx context.Context, client *report.Client, assignment wire.Config) (config.Ruleset, error) {
	var empty config.Ruleset
	data, err := client.Request(ctx, http.MethodGet, "ruleset", nil, http.StatusOK, 1024*1024)
	if err != nil {
		return empty, err
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), assignment.RulesetSHA256) {
		return empty, errors.New("assigned ruleset SHA-256 mismatch")
	}
	rules, err := config.Load(bytes.NewReader(data))
	if err != nil {
		return empty, err
	}
	if rules.BenchmarkID != assignment.BenchmarkID || rules.RulesetVersion != assignment.RulesetVersion {
		return empty, errors.New("ruleset does not match core assignment")
	}
	return rules, nil
}

func spoolEntries(dir string) ([]os.DirEntry, int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	var reports []os.DirEntry
	var total int64
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".write-") {
			return nil, 0, errors.New("incomplete spool write retained; operator recovery required")
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			return nil, 0, errors.New("unexpected spool entry")
		}
		info, err := entry.Info()
		if err != nil {
			return nil, 0, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxReportBytes {
			return nil, 0, errors.New("invalid spool file")
		}
		total += info.Size()
		reports = append(reports, entry)
	}
	if len(reports) > maxSpoolFiles || total > maxSpoolBytes {
		return nil, 0, errors.New("spool capacity exceeded; reports retained")
	}
	return reports, total, nil
}

func flushSpool(ctx context.Context, dir, agentID string, client *report.Client) error {
	entries, _, err := spoolEntries(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		data, err := readPrivate(filepath.Join(dir, entry.Name()), maxReportBytes)
		if err != nil {
			return err
		}
		var pending wire.Report
		if err := decodeJSON(data, &pending); err != nil {
			return err
		}
		if pending.AgentID != agentID || pending.ReportID+".json" != entry.Name() {
			return errors.New("spool report identity mismatch")
		}
		if err := client.Submit(ctx, pending); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
		if err := syncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

func enqueue(dir string, result wire.Report) error {
	entries, size, err := spoolEntries(dir)
	if err != nil {
		return err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if len(data) > maxReportBytes || len(entries) >= maxSpoolFiles || size+int64(len(data)) > maxSpoolBytes {
		return errors.New("spool full; no reports discarded")
	}
	return atomicJSON(filepath.Join(dir, result.ReportID+".json"), result)
}

func waitContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func runDaemon(ctx context.Context, dir, coreURL, agentID string, allowRemediation bool) error {
	coreURL = strings.TrimRight(coreURL, "/")
	// Validate transport before writing any state or making requests.
	if _, err := report.NewClient(coreURL, "validation-only"); err != nil {
		return err
	}
	if err := privateDir(dir); err != nil {
		return err
	}
	unlock, err := lockState(dir)
	if err != nil {
		return err
	}
	defer unlock()
	spool := filepath.Join(dir, "spool")
	if err := privateDir(spool); err != nil {
		return err
	}
	backoff := time.Second
	var state agentState
	for {
		state, err = loadIdentity(ctx, dir, coreURL, agentID)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil
		}
		fmt.Fprintln(os.Stderr, "agent enrollment:", err)
		// Do not enroll again after receiving credentials that could not be persisted.
		if state.AgentID != "" {
			return err
		}
		if !waitContext(ctx, backoff) {
			return nil
		}
		backoff = min(backoff*2, 5*time.Minute)
	}
	client, err := report.NewClient(coreURL, state.AgentToken)
	if err != nil {
		return err
	}
	taskBase, err := prepareTaskState(dir)
	if err != nil {
		return err
	}
	// Safety recovery is local and happens before any upload, task fetch or scan.
	if _, err := recoverLocalTasks(taskBase, state.AgentID); err != nil {
		return err
	}
	backoff = time.Second
	nextHeartbeat := time.Time{}
	for ctx.Err() == nil {
		if !time.Now().Before(nextHeartbeat) {
			_, heartbeatErr := client.Request(ctx, http.MethodPost, "heartbeat", wire.Heartbeat{Version: wire.Version, AgentID: state.AgentID, SentAt: time.Now().UTC()}, http.StatusNoContent, 0)
			if heartbeatErr != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "agent heartbeat:", heartbeatErr)
			}
			nextHeartbeat = time.Now().Add(time.Minute)
		}
		err = flushSpool(ctx, spool, state.AgentID, client)
		if err == nil {
			var base string
			base, err = prepareTaskState(dir)
			if err == nil {
				err = recoverAndFlushTasks(ctx, base, state.AgentID, client)
			}
		}
		var assignment wire.Config
		if err == nil {
			assignment, err = assignedConfig(ctx, client)
		}
		if err == nil {
			err = processTask(ctx, dir, state.AgentID, client, allowRemediation, assignment.BenchmarkID)
		}
		if err == nil && (assignment.ScanID != "" || !time.Now().Before(state.NextScan)) {
			var rules config.Ruleset
			err = checks.RequireUbuntuBenchmark(os.DirFS("/"), assignment.BenchmarkID)
			if err == nil {
				rules, err = assignedRules(ctx, client, assignment)
			}
			if err == nil && ctx.Err() == nil {
				var result wire.Report
				result, err = scan(rules, os.DirFS("/"), state.AgentID)
				if err == nil {
					result.ScanID = assignment.ScanID
					err = enqueue(spool, result)
				}
				if err == nil {
					state.NextScan = time.Now().UTC().Add(time.Duration(assignment.IntervalSeconds) * time.Second)
					if saveErr := atomicJSON(filepath.Join(dir, "identity.json"), state); saveErr != nil {
						return saveErr
					}
					err = flushSpool(ctx, spool, state.AgentID, client)
				}
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "agent delivery/schedule:", err)
			if !waitContext(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		delay := min(time.Until(state.NextScan), time.Until(nextHeartbeat), 10*time.Second)
		if delay < time.Second {
			delay = time.Second
		}
		if !waitContext(ctx, delay) {
			return nil
		}
	}
	return nil
}
