package checks

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

func loadedAuditRules() (rules []loadedAuditRule, err error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_AUDIT)
	if err != nil {
		return nil, errors.New("cannot open the read-only audit query socket")
	}
	defer func() {
		if closeErr := unix.Close(fd); err == nil && closeErr != nil {
			err = errors.New("cannot close audit query socket")
		}
	}()
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, errors.New("cannot bind audit query socket")
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return nil, errors.New("cannot identify audit query port")
	}
	local, ok := address.(*unix.SockaddrNetlink)
	if !ok || local.Pid == 0 || local.Groups != 0 {
		return nil, errors.New("invalid audit query port scope")
	}
	deadline := time.Now().Add(6 * time.Second)
	buffer := make([]byte, 64*1024)
	read := func(sequence uint32, retain bool) (result []loadedAuditRule, digest [32]byte, err error) {
		request := make([]byte, 16)
		binary.NativeEndian.PutUint32(request, 16)
		binary.NativeEndian.PutUint16(request[4:], unix.AUDIT_LIST_RULES)
		// No success ACK: it can precede the asynchronous multipart rule list.
		binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST)
		binary.NativeEndian.PutUint32(request[8:], sequence)
		binary.NativeEndian.PutUint32(request[12:], local.Pid)
		if err = unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
			return nil, digest, errors.New("cannot send read-only audit rule query")
		}
		hash := sha256.New()
		total, count := 0, 0
		for {
			left := time.Until(deadline)
			if left <= 0 {
				return nil, digest, errors.New("audit query deadline exceeded")
			}
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			n, err := unix.Poll(poll, int((left+time.Millisecond-1)/time.Millisecond))
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil || n == 0 {
				return nil, digest, errors.New("audit query unavailable or timed out")
			}
			if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return nil, digest, errors.New("audit query socket reported lost or unavailable data")
			}
			n, from, err := unix.Recvfrom(fd, buffer, unix.MSG_DONTWAIT|unix.MSG_TRUNC)
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			if err != nil || n < 16 || n > len(buffer) {
				return nil, digest, errors.New("audit datagram unavailable, malformed or larger than64KiB")
			}
			peer, ok := from.(*unix.SockaddrNetlink)
			if !ok || peer.Pid != 0 || peer.Groups != 0 {
				return nil, digest, errors.New("audit response did not originate from kernel unicast")
			}
			total += n
			if total > 16*1024*1024 {
				return nil, digest, errors.New("audit response exceeds16MiB")
			}
			packet := buffer[:n]
			for len(packet) > 0 {
				if len(packet) < 16 {
					return nil, digest, errors.New("truncated audit netlink header")
				}
				length := int(binary.NativeEndian.Uint32(packet))
				if length < 16 || length > len(packet) {
					return nil, digest, errors.New("invalid audit netlink message length")
				}
				kind, flags := binary.NativeEndian.Uint16(packet[4:]), binary.NativeEndian.Uint16(packet[6:])
				seq, pid := binary.NativeEndian.Uint32(packet[8:]), binary.NativeEndian.Uint32(packet[12:])
				if seq != sequence || (pid != 0 && pid != local.Pid) || flags&unix.NLM_F_DUMP_INTR != 0 {
					return nil, digest, errors.New("audit message identity or snapshot continuity failed")
				}
				data := packet[16:length]
				aligned := (length + 3) &^ 3
				if aligned > len(packet) {
					if length != len(packet) {
						return nil, digest, errors.New("invalid audit netlink alignment")
					}
					aligned = length
				}
				switch kind {
				case unix.NLMSG_ERROR:
					return nil, digest, errors.New("audit rule list denied or unavailable; initial namespaces and CAP_AUDIT_CONTROL may be required")
				case unix.NLMSG_DONE:
					if aligned != len(packet) {
						return nil, digest, errors.New("unexpected audit messages after list completion")
					}
					if flags&unix.NLM_F_MULTI == 0 || (len(data) != 0 && (len(data) != 4 || binary.NativeEndian.Uint32(data) != 0)) {
						return nil, digest, errors.New("invalid audit list completion")
					}
					copy(digest[:], hash.Sum(nil))
					return result, digest, nil
				case unix.AUDIT_LIST_RULES:
					if flags&unix.NLM_F_MULTI == 0 {
						return nil, digest, errors.New("audit list is not multipart")
					}
					count++
					if count > 8192 {
						return nil, digest, errors.New("audit rule count exceeds8192")
					}
					hash.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(data))))
					hash.Write(data)
					if retain {
						rule, err := decodeAuditRule(data)
						if err != nil {
							return nil, digest, err
						}
						result = append(result, rule)
					}
				default:
					return nil, digest, errors.New("unexpected audit response type; event records are not requested")
				}
				packet = packet[aligned:]
			}
		}
	}
	first, digest, err := read(1, true)
	if err != nil {
		return nil, err
	}
	_, second, err := read(2, false)
	if err != nil {
		return nil, err
	}
	if digest != second {
		return nil, errors.New("loaded audit rules changed during inspection")
	}
	return first, nil
}
