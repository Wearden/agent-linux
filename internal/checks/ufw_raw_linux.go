package checks

import (
	"errors"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The upstream decoder silently skips unknown expression names. Inspect the
// raw list and compare its count so an omitted predicate cannot become a pass.
func ufwRawExpressions(data []byte) (int, error) {
	list, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return 0, err
	}
	count := 0
	for list.Next() {
		if list.Type() != unix.NFTA_LIST_ELEM {
			return 0, errors.New("unexpected raw expression list attribute")
		}
		entry, err := netlink.NewAttributeDecoder(list.Bytes())
		if err != nil {
			return 0, err
		}
		name := ""
		hasData := false
		for entry.Next() {
			switch entry.Type() {
			case unix.NFTA_EXPR_NAME:
				if name != "" {
					return 0, errors.New("duplicate expression name")
				}
				name = entry.String()
			case unix.NFTA_EXPR_DATA:
				if hasData {
					return 0, errors.New("duplicate expression payload")
				}
				hasData = true
			default:
				return 0, errors.New("unknown expression attribute")
			}
		}
		if err := entry.Err(); err != nil {
			return 0, err
		}
		if !hasData || !oneOfPolicy(name, "counter", "meta", "payload", "ct", "bitwise", "cmp", "match", "log", "immediate", "limit") {
			return 0, errors.New("unknown or unreviewed kernel expression")
		}
		count++
		if count > 128 {
			return 0, errors.New("raw expression bound exceeded")
		}
	}
	return count, list.Err()
}
