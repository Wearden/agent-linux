//go:build !linux

package checks

import "io/fs"

func ownership(fs.FileInfo) (uint32, uint32, bool) { return 0, 0, false }

func metadataIdentity(fs.FileInfo) (nodeIdentity, bool) { return nodeIdentity{}, false }
