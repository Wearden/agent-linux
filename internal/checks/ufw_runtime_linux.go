package checks

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Wearden/proto/wire"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var ufwControlIDs = []string{"LNX-FW-002", "LNX-FW-003", "LNX-FW-004", "LNX-FW-005", "LNX-FW-006"}

type ufwConfig struct {
	values      map[string]string
	fingerprint [32]byte
	families    []nftables.TableFamily
}
type ufwChainKey struct {
	family      nftables.TableFamily
	table, name string
}
type ufwCompat struct {
	proto, flags uint32
	expressions  int
}
type ufwRule struct {
	rule   *nftables.Rule
	compat ufwCompat
}
type ufwSnapshot struct {
	chains     map[ufwChainKey]*nftables.Chain
	rules      map[ufwChainKey][]ufwRule
	generation uint32
}

func ufwConfigState(system fs.FS) (ufwConfig, error) {
	state := ufwConfig{values: map[string]string{}, families: []nftables.TableFamily{nftables.TableFamilyIPv4}}
	var fingerprint bytes.Buffer
	for _, name := range []string{"etc/ufw/ufw.conf", "etc/default/ufw"} {
		text, err := nativeRead(system, name)
		if err != nil {
			return state, errors.New("UFW configuration is unavailable or symlinked")
		}
		fingerprint.WriteString(text)
		for _, raw := range strings.Split(text, "\n") {
			line := uncomment(raw)
			if line == "" {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok || strings.ContainsAny(key, " \t") {
				return state, errors.New("UFW shell configuration is outside the reviewed assignment-only subset")
			}
			value = strings.TrimSpace(value)
			if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
				value = value[1 : len(value)-1]
			}
			if strings.ContainsAny(value, "$`\\;|&()\"'\x00") {
				return state, errors.New("dynamic UFW configuration requires manual evaluation")
			}
			if _, exists := state.values[key]; exists {
				return state, errors.New("duplicate UFW configuration key")
			}
			state.values[key] = value
		}
	}
	if !oneOfPolicy(state.values["ENABLED"], "yes", "no") {
		return state, errors.New("UFW enabled state is not explicit")
	}
	switch state.values["IPV6"] {
	case "yes":
		state.families = append(state.families, nftables.TableFamilyIPv6)
	case "no":
		entries, err := nativeEntries(system, "proc/sys/net/ipv6/conf", false)
		if err != nil {
			return state, errors.New("IPv6 is outside UFW scope but kernel disablement cannot be established")
		}
		all, defaults := false, false
		for _, entry := range entries {
			value, err := nativeRead(system, "proc/sys/net/ipv6/conf/"+entry.Name()+"/disable_ipv6")
			if err != nil || strings.TrimSpace(value) != "1" {
				return state, errors.New("IPv6 outside UFW scope is enabled or unknown on an existing interface")
			}
			fingerprint.WriteString(entry.Name() + "=" + value)
			all = all || entry.Name() == "all"
			defaults = defaults || entry.Name() == "default"
		}
		if !all || !defaults {
			return state, errors.New("IPv6 all/default disablement is not explicit")
		}
	default:
		return state, errors.New("UFW IPv6 coverage is not explicit")
	}
	// A loaded legacy ruleset can coexist with nftables and invalidate reachability.
	base := "proc/" + strconv.Itoa(os.Getpid()) + "/net"
	if info, err := nativeStat(system, base); err != nil || !info.IsDir() {
		return state, errors.New("cannot establish current-namespace legacy iptables visibility")
	}
	for _, name := range []string{"ip_tables_names", "ip6_tables_names"} {
		text, err := nativeRead(system, base+"/"+name)
		if isMissing(err) {
			continue
		}
		if err != nil {
			return state, errors.New("cannot rule out a legacy iptables backend")
		}
		if strings.TrimSpace(text) != "" {
			return state, errors.New("iptables-legacy tables coexist; nft-only UFW evaluation is unsupported")
		}
		fingerprint.WriteString(text)
	}
	state.fingerprint = sha256.Sum256(fingerprint.Bytes())
	return state, nil
}

// GETGEN is sent directly because nftables v0.3.0 exposes GenMsg decoding but no GetGen API.
func ufwGeneration(socket *netlink.Conn) (uint32, error) {
	message := netlink.Message{Header: netlink.Header{Type: netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETGEN), Flags: netlink.Request}, Data: []byte{unix.NFPROTO_UNSPEC, 0, 0, 0}}
	replies, err := socket.Execute(message)
	if err != nil {
		return 0, errors.New("nftables generation query failed")
	}
	if len(replies) != 1 || replies[0].Header.Type != netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_NEWGEN) || len(replies[0].Data) < 4 {
		return 0, errors.New("invalid nftables generation response")
	}
	decoder, err := netlink.NewAttributeDecoder(replies[0].Data[4:])
	if err != nil {
		return 0, err
	}
	decoder.ByteOrder = binary.BigEndian
	var generation uint32
	found := false
	for decoder.Next() {
		switch decoder.Type() {
		case unix.NFTA_GEN_ID:
			if found {
				return 0, errors.New("duplicate nftables generation")
			}
			generation = decoder.Uint32()
			found = true
		case unix.NFTA_GEN_PROC_PID, unix.NFTA_GEN_PROC_NAME:
		default:
			return 0, errors.New("unrecognized nftables generation attribute")
		}
	}
	if err := decoder.Err(); err != nil {
		return 0, err
	}
	if !found {
		return 0, errors.New("nftables generation is unavailable")
	}
	return generation, nil
}

func ufwRawCompatibility(socket *netlink.Conn, table *nftables.Table, chain *nftables.Chain) (map[uint64]ufwCompat, error) {
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_RULE_TABLE, Data: append([]byte(table.Name), 0)}, {Type: unix.NFTA_RULE_CHAIN, Data: append([]byte(chain.Name), 0)}})
	if err != nil {
		return nil, err
	}
	message := netlink.Message{Header: netlink.Header{Type: netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETRULE), Flags: netlink.Request | netlink.Dump}, Data: append([]byte{byte(table.Family), 0, 0, 0}, attrs...)}
	replies, err := socket.Execute(message)
	if err != nil {
		return nil, errors.New("raw rule compatibility query failed")
	}
	if len(replies) > 8192 {
		return nil, errors.New("nftables per-chain rule bound exceeded")
	}
	out := map[uint64]ufwCompat{}
	for _, reply := range replies {
		if reply.Header.Type != netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_NEWRULE) || len(reply.Data) < 4 {
			return nil, errors.New("invalid raw nftables rule response")
		}
		decoder, err := netlink.NewAttributeDecoder(reply.Data[4:])
		if err != nil {
			return nil, err
		}
		decoder.ByteOrder = binary.BigEndian
		var handle uint64
		var compat ufwCompat
		for decoder.Next() {
			switch decoder.Type() {
			case unix.NFTA_RULE_HANDLE:
				handle = decoder.Uint64()
			case unix.NFTA_RULE_TABLE:
				if decoder.String() != table.Name {
					return nil, errors.New("rule table mismatch")
				}
			case unix.NFTA_RULE_CHAIN:
				if decoder.String() != chain.Name {
					return nil, errors.New("rule chain mismatch")
				}
			case unix.NFTA_RULE_EXPRESSIONS:
				count, err := ufwRawExpressions(decoder.Bytes())
				if err != nil {
					return nil, err
				}
				compat.expressions = count
			case unix.NFTA_RULE_USERDATA, unix.NFTA_RULE_POSITION, unix.NFTA_RULE_PAD:
			case unix.NFTA_RULE_COMPAT:
				nested, err := netlink.NewAttributeDecoder(decoder.Bytes())
				if err != nil {
					return nil, err
				}
				nested.ByteOrder = binary.BigEndian
				for nested.Next() {
					switch nested.Type() {
					case unix.NFTA_RULE_COMPAT_PROTO:
						compat.proto = nested.Uint32()
					case unix.NFTA_RULE_COMPAT_FLAGS:
						compat.flags = nested.Uint32()
					default:
						return nil, errors.New("unknown compatibility attribute")
					}
				}
				if err := nested.Err(); err != nil {
					return nil, err
				}
			default:
				return nil, errors.New("unmodeled nftables rule attribute")
			}
		}
		if err := decoder.Err(); err != nil {
			return nil, err
		}
		if handle == 0 {
			return nil, errors.New("rule has no stable handle")
		}
		if _, exists := out[handle]; exists {
			return nil, errors.New("duplicate nftables rule handle")
		}
		if compat.flags & ^uint32(unix.NFT_RULE_COMPAT_F_INV) != 0 {
			return nil, errors.New("unknown compatibility flags")
		}
		out[handle] = compat
	}
	return out, nil
}

func readUFWSnapshot() (snapshot ufwSnapshot, err error) {
	defer func() {
		if recover() != nil {
			snapshot = ufwSnapshot{}
			err = errors.New("unsupported kernel expression encoding")
		}
	}()
	deadline := time.Now().Add(8 * time.Second)
	var socket *netlink.Conn
	connection, err := nftables.New(nftables.AsLasting(), nftables.WithSockOptions(func(c *netlink.Conn) error { socket = c; return c.SetDeadline(deadline) }))
	if err != nil {
		return snapshot, errors.New("cannot open bounded nftables query socket")
	}
	defer connection.CloseLasting()
	if socket == nil {
		return snapshot, errors.New("nftables socket is unavailable")
	}
	before, err := ufwGeneration(socket)
	if err != nil {
		return snapshot, err
	}
	tables, err := connection.ListTables()
	if err != nil {
		return snapshot, errors.New("nftables table query failed")
	}
	if len(tables) > 32 {
		return snapshot, errors.New("nftables table bound exceeded")
	}
	chains, err := connection.ListChains()
	if err != nil {
		return snapshot, errors.New("nftables chain query failed")
	}
	if len(chains) > 512 {
		return snapshot, errors.New("nftables chain bound exceeded")
	}
	snapshot = ufwSnapshot{chains: map[ufwChainKey]*nftables.Chain{}, rules: map[ufwChainKey][]ufwRule{}, generation: before}
	tableMap := map[ufwChainKey]*nftables.Table{}
	for _, table := range tables {
		tableMap[ufwChainKey{family: table.Family, table: table.Name}] = table
	}
	total := 0
	for _, chain := range chains {
		if chain == nil || chain.Table == nil {
			return snapshot, errors.New("invalid nftables chain identity")
		}
		table := tableMap[ufwChainKey{family: chain.Table.Family, table: chain.Table.Name}]
		if table == nil {
			return snapshot, errors.New("chain table is outside the stable dump")
		}
		key := ufwChainKey{family: table.Family, table: table.Name, name: chain.Name}
		if _, exists := snapshot.chains[key]; exists {
			return snapshot, errors.New("duplicate nftables chain")
		}
		snapshot.chains[key] = chain
		if chain.Hooknum != nil {
			canonical := table.Name == "filter" && (table.Family == nftables.TableFamilyIPv4 || table.Family == nftables.TableFamilyIPv6) && oneOfPolicy(chain.Name, "INPUT", "OUTPUT", "FORWARD")
			if !canonical {
				return snapshot, errors.New("additional hooked nftables chains require a broader packet-path evaluator")
			}
		}
		if table.Name != "filter" || (table.Family != nftables.TableFamilyIPv4 && table.Family != nftables.TableFamilyIPv6) {
			continue
		}
		if table.Flags != 0 {
			return snapshot, errors.New("dormant or owned filter tables are outside the reviewed backend")
		}
		compat, err := ufwRawCompatibility(socket, table, chain)
		if err != nil {
			return snapshot, err
		}
		rules, err := connection.GetRules(table, chain)
		if err != nil {
			return snapshot, errors.New("nftables rule decoding failed")
		}
		if len(rules) != len(compat) {
			return snapshot, errors.New("typed and raw rule snapshots disagree")
		}
		total += len(rules)
		if total > 8192 {
			return snapshot, errors.New("aggregate nftables rule bound exceeded")
		}
		for _, rule := range rules {
			if rule == nil || len(rule.Exprs) > 128 {
				return snapshot, errors.New("nftables expression bound or identity invalid")
			}
			metadata, exists := compat[rule.Handle]
			if !exists || metadata.expressions != len(rule.Exprs) {
				return snapshot, errors.New("rule handle is outside the raw snapshot")
			}
			snapshot.rules[key] = append(snapshot.rules[key], ufwRule{rule: rule, compat: metadata})
		}
	}
	after, err := ufwGeneration(socket)
	if err != nil {
		return snapshot, err
	}
	if after != before {
		return snapshot, errors.New("nftables generation changed during inspection")
	}
	return snapshot, nil
}

func ufwErrorAll(message string) map[string]wire.Finding {
	out := map[string]wire.Finding{}
	for _, id := range ufwControlIDs {
		out[id] = wire.Finding{Status: wire.Error, Evidence: message}
	}
	return out
}

func observeUFW(system fs.FS) map[string]wire.Finding {
	config, err := ufwConfigState(system)
	if err != nil {
		return ufwErrorAll(err.Error())
	}
	if config.values["ENABLED"] != "yes" {
		out := ufwErrorAll("UFW is not configured enabled")
		for id, finding := range out {
			finding.Status = wire.Fail
			out[id] = finding
		}
		return out
	}
	snapshot, err := readUFWSnapshot()
	if err != nil {
		return ufwErrorAll(err.Error())
	}
	verified, err := ufwConfigState(system)
	if err != nil || verified.fingerprint != config.fingerprint {
		return ufwErrorAll("UFW persistent or IPv6/backend state changed during inspection")
	}
	out := ufwErrorAll("live UFW proof is incomplete")
	incomingDeny, outgoingDeny, sshAllowed, logging := true, true, true, true
	activeProven := true
	activeError := "UFW before/user chain reachability is incomplete"
	logError := "configured logging has no provable reachable UFW logger on the reviewed input path"
	for _, family := range config.families {
		prefix := "ufw-"
		if family == nftables.TableFamilyIPv6 {
			prefix = "ufw6-"
		}
		for _, direction := range []struct {
			name, lower string
			hook        *nftables.ChainHook
		}{{"INPUT", "input", nftables.ChainHookInput}, {"OUTPUT", "output", nftables.ChainHookOutput}, {"FORWARD", "forward", nftables.ChainHookForward}} {
			key := ufwChainKey{family: family, table: "filter", name: direction.name}
			chain := snapshot.chains[key]
			if chain == nil || chain.Hooknum == nil || *chain.Hooknum != *direction.hook || chain.Priority == nil || *chain.Priority != 0 || chain.Type != nftables.ChainTypeFilter || chain.Device != "" || chain.Policy == nil {
				return ufwErrorAll("expected nft-backed UFW base chain hook, priority, type or policy is missing")
			}
			if *chain.Policy != nftables.ChainPolicyDrop && *chain.Policy != nftables.ChainPolicyAccept {
				return ufwErrorAll("unrecognized UFW base-chain policy")
			}
			if direction.name == "INPUT" {
				incomingDeny = incomingDeny && *chain.Policy == nftables.ChainPolicyDrop
			}
			if direction.name == "OUTPUT" {
				outgoingDeny = outgoingDeny && *chain.Policy == nftables.ChainPolicyDrop
			}
			probe := ufwProbe{family: family, direction: direction.name, destination: 65535}
			trace := newUFWTrace(snapshot, probe)
			_, traceErr := trace.walk(key, 0)
			if traceErr != nil {
				activeProven = false
				activeError = traceErr.Error()
			}
			if !trace.visited[ufwChainKey{family: family, table: "filter", name: prefix + "before-" + direction.lower}] || !trace.visited[ufwChainKey{family: family, table: "filter", name: prefix + "user-" + direction.lower}] {
				activeProven = false
			}
			if direction.name == "INPUT" {
				logging = logging && trace.logged && traceErr == nil
				if traceErr != nil {
					logError = traceErr.Error()
				}
				probe.destination = 22
				ssh := newUFWTrace(snapshot, probe)
				verdict, sshErr := ssh.walk(key, 0)
				if sshErr != nil {
					out["LNX-FW-004"] = wire.Finding{Status: wire.Error, Evidence: sshErr.Error()}
					sshAllowed = false
				} else if verdict != expr.VerdictAccept || !ssh.userAccept {
					sshAllowed = false
					out["LNX-FW-004"] = wire.Finding{Status: wire.Fail, Evidence: "new external TCP22 is denied or lacks a reachable reviewed UFW user allow"}
				}
			}
		}
	}
	if activeProven {
		out["LNX-FW-005"] = wire.Finding{Status: wire.Pass, Evidence: fmt.Sprintf("nft-backed UFW base hooks and before/user reachability verified in the current network namespace at generation %d; IPv6 scope explicit", snapshot.generation)}
	} else {
		out["LNX-FW-005"] = wire.Finding{Status: wire.Error, Evidence: activeError}
	}
	status, evidence := result(incomingDeny && config.values["DEFAULT_INPUT_POLICY"] == "DROP", "live INPUT policies and persistent UFW input defaults compared with DROP in every configured IP family")
	out["LNX-FW-002"] = wire.Finding{Status: status, Evidence: evidence}
	status, evidence = result(outgoingDeny && config.values["DEFAULT_OUTPUT_POLICY"] == "DROP", "live OUTPUT policies and persistent UFW output defaults compared with DROP in every configured IP family")
	out["LNX-FW-003"] = wire.Finding{Status: status, Evidence: evidence}
	if sshAllowed {
		out["LNX-FW-004"] = wire.Finding{Status: wire.Pass, Evidence: "reviewed new non-loopback unicast TCP SYN22 reaches a UFW user ACCEPT with no prior uncertain or denying path in every configured IP family"}
	}
	if !oneOfPolicy(config.values["LOGLEVEL"], "low", "medium", "high", "full") {
		out["LNX-FW-006"] = wire.Finding{Status: wire.Fail, Evidence: "UFW logging is not persistently enabled"}
	} else if logging {
		out["LNX-FW-006"] = wire.Finding{Status: wire.Pass, Evidence: "reachable live UFW kernel-log expressions observed for the new TCP65535 input path in every configured IP family; token-bucket log sampling and storage delivery are not attested"}
	} else {
		out["LNX-FW-006"] = wire.Finding{Status: wire.Error, Evidence: logError}
	}
	return out
}
