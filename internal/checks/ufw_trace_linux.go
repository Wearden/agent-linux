package checks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"golang.org/x/sys/unix"
)

// This is a symbolic read-only walk, never a transmitted packet. Unknown
// address/interface predicates fail closed rather than choosing an address.
type ufwProbe struct {
	family      nftables.TableFamily
	direction   string
	destination uint16
}

type ufwTrace struct {
	snapshot           ufwSnapshot
	probe              ufwProbe
	visited            map[ufwChainKey]bool
	active             map[ufwChainKey]bool
	steps              int
	logged, userAccept bool
}

func newUFWTrace(snapshot ufwSnapshot, probe ufwProbe) *ufwTrace {
	return &ufwTrace{snapshot: snapshot, probe: probe, visited: map[ufwChainKey]bool{}, active: map[ufwChainKey]bool{}}
}

func (t *ufwTrace) walk(key ufwChainKey, depth int) (expr.VerdictKind, error) {
	chain := t.snapshot.chains[key]
	if chain == nil || depth > 32 || t.active[key] {
		return 0, errors.New("missing, cyclic or excessively deep UFW chain")
	}
	t.active[key] = true
	defer delete(t.active, key)
	t.visited[key] = true
	for _, rule := range t.snapshot.rules[key] {
		t.steps++
		if t.steps > 16384 {
			return 0, errors.New("UFW traversal bound exceeded")
		}
		matched, verdict, logged, err := t.evaluate(rule)
		if err != nil {
			return 0, fmt.Errorf("UFW chain %s: %w", key.name, err)
		}
		if !matched {
			continue
		}
		if logged && strings.HasPrefix(key.name, "ufw") {
			t.logged = true
		}
		if verdict == nil {
			continue
		}
		switch verdict.Kind {
		case expr.VerdictContinue:
		case expr.VerdictAccept:
			if key.name == "ufw-user-input" || key.name == "ufw6-user-input" {
				t.userAccept = true
			}
			return verdict.Kind, nil
		case expr.VerdictDrop, expr.VerdictReturn:
			return verdict.Kind, nil
		case expr.VerdictJump, expr.VerdictGoto:
			child := ufwChainKey{family: key.family, table: key.table, name: verdict.Chain}
			if target := t.snapshot.chains[child]; target == nil || target.Hooknum != nil {
				return 0, errors.New("UFW jump target is not a regular chain")
			}
			result, err := t.walk(child, depth+1)
			if err != nil {
				return 0, err
			}
			if result != expr.VerdictReturn {
				return result, nil
			}
			if verdict.Kind == expr.VerdictGoto {
				return t.end(chain), nil
			}
		default:
			return 0, errors.New("unsupported UFW verdict")
		}
	}
	return t.end(chain), nil
}

func (t *ufwTrace) end(chain *nftables.Chain) expr.VerdictKind {
	if chain.Hooknum == nil {
		return expr.VerdictReturn
	}
	if chain.Policy != nil && *chain.Policy == nftables.ChainPolicyAccept {
		return expr.VerdictAccept
	}
	return expr.VerdictDrop
}

type ufwRegister struct {
	data        []byte
	nonLoopback bool
}

func (t *ufwTrace) evaluate(rule ufwRule) (bool, *expr.Verdict, bool, error) {
	unknown := errors.New("packet predicate or side effect is outside the reviewed symbolic subset")
	if rule.compat.proto != 0 {
		matched := rule.compat.proto == unix.IPPROTO_TCP
		if rule.compat.flags&unix.NFT_RULE_COMPAT_F_INV != 0 {
			matched = !matched
		}
		if !matched {
			return false, nil, false, nil
		}
	} else if rule.compat.flags != 0 {
		return false, nil, false, unknown
	}
	registers := map[uint32]ufwRegister{}
	var verdict *expr.Verdict
	logged := false
	for index, raw := range rule.rule.Exprs {
		if verdict != nil {
			return false, nil, false, errors.New("expressions follow a terminal verdict")
		}
		switch e := raw.(type) {
		case *expr.Counter:
		case *expr.Meta:
			if e.SourceRegister {
				return false, nil, false, unknown
			}
			var r ufwRegister
			switch e.Key {
			case expr.MetaKeyL4PROTO:
				r.data = []byte{unix.IPPROTO_TCP}
			case expr.MetaKeyNFPROTO:
				r.data = []byte{byte(t.probe.family)}
			case expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME:
				r.nonLoopback = true
			default:
				return false, nil, false, unknown
			}
			registers[e.Register] = r
		case *expr.Payload:
			if e.OperationType != expr.PayloadLoad {
				return false, nil, false, unknown
			}
			var data []byte
			switch {
			case e.Base == expr.PayloadBaseNetworkHeader && e.Len == 1 && ((t.probe.family == nftables.TableFamilyIPv4 && e.Offset == 9) || (t.probe.family == nftables.TableFamilyIPv6 && e.Offset == 6)):
				data = []byte{unix.IPPROTO_TCP}
			case e.Base == expr.PayloadBaseTransportHeader && e.Offset == 2 && e.Len == 2:
				data = binary.BigEndian.AppendUint16(nil, t.probe.destination)
			case e.Base == expr.PayloadBaseTransportHeader && e.Offset == 13 && e.Len == 1:
				data = []byte{2}
			default:
				return false, nil, false, unknown
			}
			registers[e.DestRegister] = ufwRegister{data: data}
		case *expr.Ct:
			if e.SourceRegister || e.Key != expr.CtKeySTATE {
				return false, nil, false, unknown
			}
			registers[e.Register] = ufwRegister{data: binary.NativeEndian.AppendUint32(nil, expr.CtStateBitNEW)}
		case *expr.Bitwise:
			r := registers[e.SourceRegister]
			if e.Len == 0 || int(e.Len) > len(r.data) || len(e.Mask) != int(e.Len) || len(e.Xor) != int(e.Len) {
				return false, nil, false, unknown
			}
			data := make([]byte, e.Len)
			for i := range data {
				data[i] = (r.data[i] & e.Mask[i]) ^ e.Xor[i]
			}
			registers[e.DestRegister] = ufwRegister{data: data}
		case *expr.Cmp:
			r := registers[e.Register]
			if e.Op != expr.CmpOpEq && e.Op != expr.CmpOpNeq {
				return false, nil, false, unknown
			}
			var equal bool
			if r.nonLoopback {
				if len(e.Data) < 3 || len(e.Data) > 16 || !bytes.Equal(bytes.TrimRight(e.Data, "\x00"), []byte("lo")) {
					return false, nil, false, unknown
				}
				equal = false
			} else {
				if len(e.Data) == 0 || len(e.Data) > len(r.data) {
					return false, nil, false, unknown
				}
				equal = bytes.Equal(r.data[:len(e.Data)], e.Data)
			}
			if (e.Op == expr.CmpOpEq) != equal {
				return false, nil, false, nil
			}
		case *expr.Match:
			matched, err := t.match(e, rule.compat)
			if err != nil {
				return false, nil, false, err
			}
			if !matched {
				return false, nil, false, nil
			}
		case *expr.Log:
			if e.Group != 0 || e.Level > expr.LogLevelDebug || !bytes.HasPrefix(e.Data, []byte("[UFW ")) {
				return false, nil, false, unknown
			}
			logged = true
		case *expr.Limit:
			// A token bucket is only modeled as a configured log sampler.
			// It may never control an accept/drop/jump decision in this subset.
			if e.Over || e.Rate == 0 || e.Unit == 0 || e.Type != expr.LimitTypePkts {
				return false, nil, false, unknown
			}
			for _, tail := range rule.rule.Exprs[index+1:] {
				switch tail.(type) {
				case *expr.Counter, *expr.Log:
				default:
					return false, nil, false, unknown
				}
			}
		case *expr.Verdict:
			verdict = e
		default:
			return false, nil, false, unknown
		}
	}
	return true, verdict, logged, nil
}

func (t *ufwTrace) match(e *expr.Match, compat ufwCompat) (bool, error) {
	unknown := errors.New("xtables match is outside the reviewed symbolic subset")
	switch info := e.Info.(type) {
	case *xt.Comment:
		if e.Name == "comment" && e.Rev == 0 {
			return true, nil
		}
	case *xt.Tcp:
		if e.Name != "tcp" || e.Rev != 0 || compat.proto != unix.IPPROTO_TCP || compat.flags != 0 || info.InvFlags & ^xt.TcpInvMask != 0 || info.Option != 0 || info.InvFlags&xt.TcpInvOption != 0 {
			return false, unknown
		}
		if info.SrcPorts != [2]uint16{0, 65535} || info.InvFlags&xt.TcpInvSrcPorts != 0 || info.DstPorts[0] > info.DstPorts[1] {
			return false, unknown
		}
		destination := t.probe.destination >= info.DstPorts[0] && t.probe.destination <= info.DstPorts[1]
		if info.InvFlags&xt.TcpInvDestPorts != 0 {
			destination = !destination
		}
		flags := uint8(2)&info.FlagsMask == info.FlagsCmp
		if info.InvFlags&xt.TcpInvFlags != 0 {
			flags = !flags
		}
		return destination && flags, nil
	case *xt.ConntrackMtinfo1:
		if e.Name == "conntrack" && e.Rev == 1 {
			return ufwConntrack(info.ConntrackMtinfoBase, uint16(info.StateMask))
		}
	case *xt.ConntrackMtinfo2:
		if e.Name == "conntrack" && e.Rev == 2 {
			return ufwConntrack(info.ConntrackMtinfoBase, info.StateMask)
		}
	case *xt.ConntrackMtinfo3:
		if e.Name == "conntrack" && e.Rev == 3 {
			return ufwConntrack(info.ConntrackMtinfoBase, info.StateMask)
		}
	case *xt.AddrTypeV1:
		if e.Name == "addrtype" && e.Rev == 1 && info.Flags == 0 && info.Source == 0 && info.Dest != 0 && t.probe.direction == "INPUT" {
			return info.Dest&uint16(xt.AddrTypeLocal) != 0, nil
		}
	}
	return false, unknown
}

func ufwConntrack(info xt.ConntrackMtinfoBase, state uint16) (bool, error) {
	if info.MatchFlags != uint16(xt.ConntrackState) || info.InvertFlags & ^uint16(xt.ConntrackState) != 0 {
		return false, errors.New("conntrack match contains unmodeled fields")
	}
	matched := state&uint16(expr.CtStateBitNEW) != 0
	if info.InvertFlags&uint16(xt.ConntrackState) != 0 {
		matched = !matched
	}
	return matched, nil
}
