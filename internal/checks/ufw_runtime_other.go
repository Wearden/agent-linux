//go:build !linux

package checks

import (
	"github.com/Wearden/proto/wire"
	"io/fs"
)

func observeUFW(fs.FS) map[string]wire.Finding {
	out := map[string]wire.Finding{}
	for _, id := range []string{"LNX-FW-002", "LNX-FW-003", "LNX-FW-004", "LNX-FW-005", "LNX-FW-006"} {
		out[id] = wire.Finding{Status: wire.Error, Evidence: "live UFW observation requires Linux nftables netlink support"}
	}
	return out
}
