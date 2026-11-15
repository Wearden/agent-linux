package checks

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/Wearden/proto/wire"
)

type nodeIdentity struct{ Device, Inode, UID, GID uint64 }

func localOwnerIDs(system fs.FS) (map[uint64]bool, map[uint64]bool, error) {
	nss, err := nativeRead(system, "etc/nsswitch.conf")
	if err != nil {
		return nil, nil, errors.New("cannot establish local-only NSS identity policy")
	}
	seen := map[string]bool{}
	for _, raw := range strings.Split(nss, "\n") {
		line := uncomment(raw)
		key, value, ok := strings.Cut(line, ":")
		key = strings.TrimSpace(key)
		if !ok || key != "passwd" && key != "group" {
			continue
		}
		if seen[key] || strings.Join(strings.Fields(value), " ") != "files" {
			return nil, nil, errors.New("external, dynamic or conditional NSS ownership requires manual evaluation")
		}
		seen[key] = true
	}
	if !seen["passwd"] || !seen["group"] {
		return nil, nil, errors.New("passwd/group NSS lookup sources are implicit")
	}
	uids, gids := map[uint64]bool{}, map[uint64]bool{}
	for _, table := range []struct {
		name   string
		fields int
		ids    map[uint64]bool
	}{{"etc/passwd", 7, uids}, {"etc/group", 4, gids}} {
		data, err := nativeRead(system, table.name)
		if err != nil {
			return nil, nil, errors.New("cannot inspect public local account/group numeric metadata")
		}
		for _, line := range strings.Split(data, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			fields := strings.Split(line, ":")
			if len(fields) != table.fields || fields[0] == "" || strings.HasPrefix(fields[0], "+") || strings.HasPrefix(fields[0], "-") {
				return nil, nil, errors.New("local identity file contains malformed or compatibility entries")
			}
			// Never consult shadow, gshadow, opasswd or any history/hash database.
			if !oneOfPolicy(fields[1], "x", "*", "!", "!!", "") {
				return nil, nil, errors.New("public identity file contains unreviewed authentication-field syntax")
			}
			id, err := strconv.ParseUint(fields[2], 10, 32)
			if err != nil {
				return nil, nil, errors.New("invalid local numeric owner identity")
			}
			if table.fields == 7 {
				if _, err := strconv.ParseUint(fields[3], 10, 32); err != nil {
					return nil, nil, errors.New("invalid local primary group identity")
				}
			}
			table.ids[id] = true
		}
	}
	if len(uids) == 0 || len(gids) == 0 {
		return nil, nil, errors.New("local account/group identity set is empty")
	}
	return uids, gids, nil
}

func filesystemAudit(system fs.FS, target string) (string, string) {
	if !oneOfPolicy(target, "world-writable-files", "unsticky-directories", "orphaned-owners") {
		return wire.Error, "unknown local metadata audit"
	}
	links, ok := system.(fs.ReadLinkFS)
	if !ok {
		return wire.Error, "filesystem cannot inspect links and native device/owner metadata"
	}
	root, err := links.Lstat(".")
	if err != nil || !root.IsDir() || root.Mode()&fs.ModeSymlink != 0 {
		return wire.Error, "cannot establish real filesystem audit root"
	}
	rootID, ok := metadataIdentity(root)
	if !ok {
		return wire.Error, "native filesystem device identity is unavailable"
	}
	var uids, gids map[uint64]bool
	if target == "orphaned-owners" {
		uids, gids, err = localOwnerIDs(system)
		if err != nil {
			return wire.Error, err.Error()
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	visited, violations := 0, 0
	const maxEntries = 100000
	incomplete := ""
	deviceSkips := 0
	var visit func(string, int) error
	visit = func(name string, depth int) error {
		if visited >= maxEntries || time.Now().After(deadline) {
			return errors.New("metadata audit reached its entry or time bound")
		}
		if depth > 64 {
			return errors.New("metadata audit reached its directory-depth bound")
		}
		visited++
		info, err := links.Lstat(name)
		if err != nil {
			return errors.New("metadata audit encountered an inaccessible or changing entry")
		}
		identity, ok := metadataIdentity(info)
		if !ok {
			return errors.New("metadata audit cannot obtain native device or owner identity")
		}
		switch target {
		case "world-writable-files":
			if info.Mode().IsRegular() && info.Mode().Perm()&0002 != 0 {
				violations++
			}
		case "unsticky-directories":
			if info.IsDir() && info.Mode().Perm()&0002 != 0 && info.Mode()&fs.ModeSticky == 0 {
				violations++
			}
		case "orphaned-owners":
			if !uids[identity.UID] || !gids[identity.GID] {
				violations++
			}
		}
		// Like find -xdev, evaluate a mountpoint's own metadata but do not descend.
		if identity.Device != rootID.Device {
			deviceSkips++
			return nil
		}
		if name == "proc" || name == "sys" || name == "dev" {
			incomplete = "an excluded proc/sys/dev tree shares the root device; a complete root-device audit cannot be claimed"
			return nil
		}
		if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
			return nil
		}
		// Directory streams are read in bounded batches. No regular file is opened.
		directory, err := system.Open(name)
		if err != nil {
			return errors.New("metadata audit cannot open a directory")
		}
		defer directory.Close()
		opened, err := directory.Stat()
		if err != nil {
			return errors.New("cannot verify opened metadata directory")
		}
		openedID, ok := metadataIdentity(opened)
		if !ok || !opened.IsDir() || openedID.Device != identity.Device || openedID.Inode != identity.Inode {
			return errors.New("metadata directory changed between inspection and opening")
		}
		reader, ok := directory.(fs.ReadDirFile)
		if !ok {
			return errors.New("filesystem does not expose bounded directory enumeration")
		}
		for {
			if time.Now().After(deadline) {
				return errors.New("metadata audit reached its time bound")
			}
			entries, readErr := reader.ReadDir(128)
			for _, entry := range entries {
				if !fs.ValidPath(entry.Name()) || strings.Contains(entry.Name(), "/") {
					return errors.New("metadata directory contains an invalid entry name")
				}
				if err := visit(path.Join(name, entry.Name()), depth+1); err != nil {
					return err
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					latest, err := directory.Stat()
					if err != nil || !latest.ModTime().Equal(opened.ModTime()) {
						return errors.New("metadata directory changed while enumerating")
					}
					return nil
				}
				return errors.New("metadata directory enumeration failed")
			}
			if len(entries) == 0 {
				return errors.New("metadata directory enumeration made no progress")
			}
		}
	}
	err = visit(".", 0)
	// A witnessed violation disproves the root-device policy even if a later
	// traversal limit prevents proving that there are no additional violations.
	if violations > 0 {
		return wire.Fail, fmt.Sprintf("root-device metadata audit observed %d policy violations in %d entries; finding contains no file paths or contents", violations, visited)
	}
	if err != nil {
		return wire.Error, err.Error() + "; no complete-pass claim"
	}
	if incomplete != "" {
		return wire.Error, incomplete
	}
	return wire.Pass, fmt.Sprintf("complete bounded root-device metadata audit: %d entries, %d other-device entries excluded, no policy violations; traversal opens no regular files", visited, deviceSkips)
}
