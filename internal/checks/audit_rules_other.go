//go:build !linux

package checks

import (
	"fmt"
	"github.com/Wearden/proto/wire"
)

func observeAuditRules() map[string]wire.Finding {
	out := map[string]wire.Finding{}
	for n := 3; n <= 12; n++ {
		out[fmt.Sprintf("LNX-AUD-%03d", n)] = wire.Finding{Status: wire.Error, Evidence: "loaded audit-rule inspection requires Linux"}
	}
	return out
}
