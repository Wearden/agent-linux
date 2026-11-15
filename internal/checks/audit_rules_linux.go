package checks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/Wearden/proto/wire"
	"golang.org/x/sys/unix"
)

type auditField struct {
	kind, value, operation uint32
	text                   string
}
type loadedAuditRule struct {
	flags, action uint32
	mask          [64]uint32
	fields        []auditField
}

func decodeAuditRule(data []byte) (loadedAuditRule, error) {
	var rule loadedAuditRule
	const header = 1040 // Three u32s, four arrays of64 u32s and the string-buffer length.
	if len(data) < header || len(data) > header+1024*1024 {
		return rule, errors.New("audit rule size is outside the reviewed bounds")
	}
	u32 := func(offset int) uint32 { return binary.NativeEndian.Uint32(data[offset : offset+4]) }
	rule.flags, rule.action = u32(0), u32(4)
	count, length := u32(8), u32(header-4)
	if count > unix.AUDIT_MAX_FIELDS || int(length) != len(data)-header {
		return rule, errors.New("invalid audit field count or string buffer")
	}
	for i := range rule.mask {
		rule.mask[i] = u32(12 + i*4)
	}
	buffer := data[header:]
	for i := 0; i < int(count); i++ {
		field := auditField{kind: u32(268 + i*4), value: u32(524 + i*4), operation: u32(780 + i*4)}
		if field.kind&unix.AUDIT_NEGATE != 0 {
			return rule, errors.New("legacy negated audit field encoding requires review")
		}
		switch field.kind {
		case unix.AUDIT_WATCH, unix.AUDIT_DIR, unix.AUDIT_EXE, unix.AUDIT_FILTERKEY,
			unix.AUDIT_SUBJ_USER, unix.AUDIT_SUBJ_ROLE, unix.AUDIT_SUBJ_TYPE, unix.AUDIT_SUBJ_SEN, unix.AUDIT_SUBJ_CLR,
			unix.AUDIT_OBJ_USER, unix.AUDIT_OBJ_ROLE, unix.AUDIT_OBJ_TYPE, unix.AUDIT_OBJ_LEV_LOW, unix.AUDIT_OBJ_LEV_HIGH:
			if uint64(field.value) > uint64(len(buffer)) {
				return rule, errors.New("truncated audit string field")
			}
			field.text = string(buffer[:field.value])
			buffer = buffer[field.value:]
			if strings.ContainsRune(field.text, 0) {
				return rule, errors.New("unreviewed audit string termination")
			}
		}
		rule.fields = append(rule.fields, field)
	}
	if len(buffer) != 0 {
		return rule, errors.New("unmodeled audit string fields")
	}
	return rule, nil
}

func auditWatch(rule loadedAuditRule, paths ...string) bool {
	for _, field := range rule.fields {
		if (field.kind != unix.AUDIT_WATCH && field.kind != unix.AUDIT_DIR) || field.operation != unix.AUDIT_EQUAL {
			continue
		}
		for _, name := range paths {
			if strings.TrimRight(field.text, "/") == name {
				return true
			}
		}
	}
	return false
}

func auditCalls(rule loadedAuditRule, id string) (bool, error) {
	var architecture uint32
	for _, field := range rule.fields {
		if field.kind == unix.AUDIT_ARCH {
			if architecture != 0 || field.operation != unix.AUDIT_EQUAL {
				return false, errors.New("unreviewed audit architecture predicate")
			}
			architecture = field.value
		}
	}
	var selected []uint32
	switch architecture {
	case unix.AUDIT_ARCH_X86_64:
		switch id {
		case "LNX-AUD-004":
			selected = []uint32{159, 164, 227}
		case "LNX-AUD-006":
			selected = []uint32{170, 171}
		case "LNX-AUD-010":
			selected = []uint32{90, 91, 92, 93, 94, 188, 189, 190, 260, 268, 452}
		case "LNX-AUD-012":
			selected = []uint32{59, 322}
		}
	case unix.AUDIT_ARCH_I386:
		switch id {
		case "LNX-AUD-004":
			selected = []uint32{79, 124, 264, 404}
		case "LNX-AUD-006":
			selected = []uint32{74, 121}
		case "LNX-AUD-010":
			selected = []uint32{15, 16, 94, 95, 182, 198, 207, 212, 226, 227, 228, 298, 306, 452}
		case "LNX-AUD-012":
			selected = []uint32{11, 358}
		}
	default:
		for _, bits := range rule.mask {
			if bits != 0 {
				return false, errors.New("audit syscall rule lacks a reviewed explicit x86 architecture")
			}
		}
		return false, nil
	}
	for _, number := range selected {
		if rule.mask[number/32]&(uint32(1)<<(number%32)) != 0 {
			return true, nil
		}
	}
	return false, nil
}

func observeAuditRules() map[string]wire.Finding {
	out := map[string]wire.Finding{}
	rules, err := loadedAuditRules()
	for number := 3; number <= 12; number++ {
		id := fmt.Sprintf("LNX-AUD-%03d", number)
		if err != nil {
			out[id] = wire.Finding{Status: wire.Error, Evidence: err.Error()}
			continue
		}
		found := false
		var uncertain error
		for _, rule := range rules {
			if rule.action != unix.AUDIT_ALWAYS || rule.flags&^uint32(unix.AUDIT_FILTER_PREPEND) != unix.AUDIT_FILTER_EXIT {
				continue
			}
			switch id {
			case "LNX-AUD-003":
				found = auditWatch(rule, "/etc/sudoers", "/etc/sudoers.d")
			case "LNX-AUD-005":
				found = auditWatch(rule, "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow")
			case "LNX-AUD-006":
				found = auditWatch(rule, "/etc/hosts", "/etc/issue")
			case "LNX-AUD-007":
				for _, field := range rule.fields {
					if (field.kind == unix.AUDIT_WATCH || field.kind == unix.AUDIT_DIR) && field.operation == unix.AUDIT_EQUAL && (field.text == "/etc/apparmor" || strings.HasPrefix(field.text, "/etc/apparmor/") || field.text == "/etc/apparmor.d" || strings.HasPrefix(field.text, "/etc/apparmor.d/")) {
						found = true
					}
				}
			case "LNX-AUD-008":
				found = auditWatch(rule, "/var/lastlog", "/var/log/lastlog", "/var/faillock", "/var/log/faillock", "/var/tallylog", "/var/log/tallylog")
			case "LNX-AUD-009":
				found = auditWatch(rule, "/run/utmp", "/var/run/utmp", "/var/log/wtmp", "/var/log/btmp")
			case "LNX-AUD-011":
				for _, field := range rule.fields {
					if field.kind == unix.AUDIT_EXIT && field.operation == unix.AUDIT_EQUAL && int32(field.value) == -int32(unix.EACCES) {
						found = true
					}
				}
			case "LNX-AUD-012":
				for _, field := range rule.fields {
					if field.kind == unix.AUDIT_FIELD_COMPARE && field.operation == unix.AUDIT_NOT_EQUAL && field.value == unix.AUDIT_COMPARE_UID_TO_EUID {
						found = true
					}
				}
			}
			if !found && (id == "LNX-AUD-004" || id == "LNX-AUD-006" || id == "LNX-AUD-010" || id == "LNX-AUD-012") {
				match, err := auditCalls(rule, id)
				found = match
				if err != nil {
					uncertain = err
				}
			}
			if found {
				break
			}
		}
		finding := wire.Finding{Status: wire.Fail, Evidence: "no reviewed matching selector in loaded always/exit audit rules"}
		if found {
			finding.Status = wire.Pass
			finding.Evidence = "matching selector present in stable loaded always/exit audit metadata; suppression, other predicates and event delivery are not attested"
		} else if uncertain != nil {
			finding.Status = wire.Error
			finding.Evidence = uncertain.Error()
		}
		out[id] = finding
	}
	return out
}
