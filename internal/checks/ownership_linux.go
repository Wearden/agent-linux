package checks

import (
	"io/fs"
	"syscall"
)

func ownership(info fs.FileInfo) (uint32, uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return stat.Uid, stat.Gid, true
}

func metadataIdentity(info fs.FileInfo) (nodeIdentity, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nodeIdentity{}, false
	}
	return nodeIdentity{Device: uint64(stat.Dev), Inode: uint64(stat.Ino), UID: uint64(stat.Uid), GID: uint64(stat.Gid)}, true
}
