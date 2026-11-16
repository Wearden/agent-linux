package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Wearden/agent-linux/internal/report"
	"github.com/Wearden/proto/wire"
)

// Operational log shipping. Entries are short status lines written by the agent
// itself (never evidence or file contents). They are kept in a bounded queue that
// is persisted in the private state directory so a core outage or restart does
// not lose them, and are delivered in batches by the daemon loop.
const (
	logQueueMax    = 500
	logDedupWindow = 5 * time.Minute
)

type logShipper struct {
	mu      sync.Mutex
	path    string
	entries []wire.LogEntry
}

var shipper *logShipper

func newLogShipper(dir string) *logShipper {
	s := &logShipper{path: filepath.Join(dir, "log-queue.json")}
	if data, err := readPrivate(s.path, 1024*1024); err == nil {
		var saved []wire.LogEntry
		if decodeJSON(data, &saved) == nil {
			for _, e := range saved {
				if validLogEntry(e) && len(s.entries) < logQueueMax {
					s.entries = append(s.entries, e)
				}
			}
		}
	}
	return s
}

func validLogEntry(e wire.LogEntry) bool {
	return wire.LogBatch{Version: wire.Version, AgentID: "x", Entries: []wire.LogEntry{e}}.Validate() == nil
}

func cleanLogText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > wire.MaxLogMessage {
		s = s[:wire.MaxLogMessage]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	if s == "" {
		return "event"
	}
	return s
}

// agentLog always writes to stderr and, once the daemon has started the shipper,
// queues the line for delivery to core.
func agentLog(level, format string, args ...any) {
	message := cleanLogText(fmt.Sprintf(format, args...))
	fmt.Fprintln(os.Stderr, "agent:", level, message)
	if shipper != nil {
		shipper.add(level, message)
	}
}

func (s *logShipper) add(level, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if n := len(s.entries); n > 0 {
		last := s.entries[n-1]
		if last.Level == level && last.Message == message && now.Sub(last.Time) < logDedupWindow {
			return // collapse a repeating failure into one line per window
		}
	}
	s.entries = append(s.entries, wire.LogEntry{Time: now, Level: level, Message: message})
	if len(s.entries) > logQueueMax {
		s.entries = s.entries[len(s.entries)-logQueueMax:]
	}
	_ = atomicJSON(s.path, s.entries) // best effort: the in-memory queue still delivers
}

// flush sends up to one batch. Entries are removed only after core accepted them.
func (s *logShipper) flush(ctx context.Context, client *report.Client, agentID string) error {
	s.mu.Lock()
	n := min(len(s.entries), wire.MaxLogEntries)
	batch := append([]wire.LogEntry(nil), s.entries[:n]...)
	s.mu.Unlock()
	if n == 0 {
		return nil
	}
	if _, err := client.Request(ctx, http.MethodPost, "logs", wire.LogBatch{Version: wire.Version, AgentID: agentID, Entries: batch}, http.StatusNoContent, 0); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= n {
		s.entries = append([]wire.LogEntry(nil), s.entries[n:]...)
	}
	_ = atomicJSON(s.path, s.entries)
	return nil
}
