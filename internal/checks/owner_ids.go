package checks

import "io/fs"

// LocalOwnerIDs exposes the public passwd/group numeric identity sets used by
// the orphaned-owner audit; shadow and hash databases are never consulted.
func LocalOwnerIDs(system fs.FS) (map[uint64]bool, map[uint64]bool, error) {
	return localOwnerIDs(system)
}
