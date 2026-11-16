package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Wearden/agent-linux/internal/checks"
)

// Bounded root-device metadata remediation for USR-007/008/009. Only mode bits
// or numeric owners change, each object is identity-checked through an opened
// no-follow descriptor, and the exact original state is journaled first.
const fsMetaMaxChanges = 4096

type fsMetaEntry struct {
	Path     string `json:"p"`
	Dev      uint64 `json:"d"`
	Ino      uint64 `json:"i"`
	Mode     uint32 `json:"m"`
	UID      uint32 `json:"u"`
	GID      uint32 `json:"g"`
	NewMode  uint32 `json:"nm"`
	NewUID   uint32 `json:"nu"`
	NewGID   uint32 `json:"ng"`
	NewChown bool   `json:"nc"`
}

func fsMetaTarget(id string) (string, bool) {
	switch id {
	case "LNX-USR-007":
		return "world-writable-files", true
	case "LNX-USR-008":
		return "unsticky-directories", true
	case "LNX-USR-009":
		return "orphaned-owners", true
	}
	return "", false
}

func snapshotFSMeta(p mutationPlan) (ruleBackup, error) {
	backup := ruleBackup{Kind: "fsmeta", Path: p.Path, Exists: true}
	var uids, gids map[uint64]bool
	if p.Payload == "orphaned-owners" {
		var err error
		if uids, gids, err = checks.LocalOwnerIDs(os.DirFS("/")); err != nil {
			return backup, err
		}
	}
	root, err := os.Lstat("/")
	if err != nil {
		return backup, errors.New("cannot inspect filesystem root")
	}
	rootStat, ok := root.Sys().(*syscall.Stat_t)
	if !ok {
		return backup, errors.New("native device identity is unavailable")
	}
	deadline := time.Now().Add(20 * time.Second)
	visited := 0
	var entries []fsMetaEntry
	var visit func(string, int) error
	visit = func(name string, depth int) error {
		if visited >= 100000 || depth > 64 || time.Now().After(deadline) {
			return errors.New("metadata remediation scan reached its entry, depth or time bound")
		}
		visited++
		info, err := os.Lstat(name)
		if err != nil {
			return errors.New("metadata remediation scan met an inaccessible or changing entry")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("native owner identity is unavailable")
		}
		entry := fsMetaEntry{Path: name, Dev: uint64(st.Dev), Ino: st.Ino, Mode: st.Mode & 07777, UID: st.Uid, GID: st.Gid}
		entry.NewMode, entry.NewUID, entry.NewGID = entry.Mode, st.Uid, st.Gid
		selected := false
		switch p.Payload {
		case "world-writable-files":
			if info.Mode().IsRegular() && entry.Mode&0002 != 0 {
				entry.NewMode, selected = entry.Mode&^0002, true
			}
		case "unsticky-directories":
			if info.IsDir() && entry.Mode&0002 != 0 && entry.Mode&01000 == 0 {
				entry.NewMode, selected = entry.Mode|01000, true
			}
		case "orphaned-owners":
			if !uids[uint64(st.Uid)] {
				entry.NewUID, entry.NewChown, selected = 0, true, true
			}
			if !gids[uint64(st.Gid)] {
				entry.NewGID, entry.NewChown, selected = 0, true, true
			}
		}
		if selected {
			if len(entries) >= fsMetaMaxChanges {
				return errors.New("more objects need remediation than the reviewed per-task bound; no change attempted")
			}
			entries = append(entries, entry)
		}
		if uint64(st.Dev) != uint64(rootStat.Dev) {
			return nil
		}
		if name == "/proc" || name == "/sys" || name == "/dev" {
			return nil
		}
		if !info.IsDir() {
			return nil
		}
		children, err := os.ReadDir(name)
		if err != nil {
			return errors.New("metadata remediation scan cannot enumerate a directory")
		}
		for _, child := range children {
			if err := visit(filepath.Join(name, child.Name()), depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit("/", 0); err != nil {
		return backup, err
	}
	data, err := json.Marshal(entries)
	if err != nil || len(data) > 4*1024*1024 {
		return backup, errors.New("metadata journal exceeds its reviewed size")
	}
	backup.Data = data
	return backup, nil
}

func openMetaEntry(e fsMetaEntry) (*os.File, error) {
	if !filepath.IsAbs(e.Path) || strings.ContainsRune(e.Path, 0) {
		return nil, errors.New("invalid journaled path")
	}
	f, err := os.OpenFile(e.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil || uint64(st.Dev) != e.Dev || st.Ino != e.Ino {
		f.Close()
		return nil, errors.New("journaled object identity changed")
	}
	return f, nil
}

func fsMetaState(f *os.File) (mode, uid, gid uint32, err error) {
	var st syscall.Stat_t
	if err = syscall.Fstat(int(f.Fd()), &st); err != nil {
		return
	}
	return st.Mode & 07777, st.Uid, st.Gid, nil
}

func decodeFSMeta(backup *ruleBackup) ([]fsMetaEntry, error) {
	var entries []fsMetaEntry
	if err := json.Unmarshal(backup.Data, &entries); err != nil || len(entries) > fsMetaMaxChanges {
		return nil, errors.New("invalid metadata journal")
	}
	return entries, nil
}

func specialBits(mode uint32) os.FileMode {
	m := os.FileMode(mode & 0777)
	if mode&04000 != 0 {
		m |= os.ModeSetuid
	}
	if mode&02000 != 0 {
		m |= os.ModeSetgid
	}
	if mode&01000 != 0 {
		m |= os.ModeSticky
	}
	return m
}

func applyFSMeta(backup *ruleBackup) error {
	entries, err := decodeFSMeta(backup)
	if err != nil {
		return err
	}
	for _, e := range entries {
		f, err := openMetaEntry(e)
		if err != nil {
			return err
		}
		mode, uid, gid, err := fsMetaState(f)
		if err != nil || mode != e.Mode || uid != e.UID || gid != e.GID {
			f.Close()
			return errors.New("object metadata changed after the durable snapshot")
		}
		if e.NewChown {
			err = f.Chown(int(e.NewUID), int(e.NewGID))
		} else {
			err = f.Chmod(specialBits(e.NewMode))
		}
		f.Close()
		if err != nil {
			return errors.New("cannot change object metadata")
		}
	}
	return nil
}

// Recovery restores only objects still matching either journaled state; any
// third-party metadata change is refused rather than overwritten. A chown may
// have cleared set-id bits, so owner-changed objects are matched by owner only.
func restoreFSMeta(backup *ruleBackup) error {
	if !backup.Exists || backup.Companion != nil || backup.ParentCreated {
		return errors.New("invalid metadata backup shape")
	}
	entries, err := decodeFSMeta(backup)
	if err != nil {
		return err
	}
	failed := 0
	for _, e := range entries {
		f, err := openMetaEntry(e)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				failed++
			}
			continue
		}
		mode, uid, gid, err := fsMetaState(f)
		original := err == nil && mode == e.Mode && uid == e.UID && gid == e.GID
		applied := err == nil && uid == e.NewUID && gid == e.NewGID && (e.NewChown || mode == e.NewMode)
		switch {
		case err != nil:
			failed++
		case original:
		case applied:
			if e.NewChown {
				err = f.Chown(int(e.UID), int(e.GID))
			}
			if err == nil {
				err = f.Chmod(specialBits(e.Mode))
			}
			if err != nil {
				failed++
			}
		default:
			failed++
		}
		f.Close()
	}
	if failed > 0 {
		return errors.New("some journaled objects could not be restored or changed externally; manual review is required")
	}
	return nil
}
