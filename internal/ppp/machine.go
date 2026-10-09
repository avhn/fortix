package ppp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// Negotiation errors distinguish bounded retry exhaustion from unsupported links.
var (
	ErrNegotiation = errors.New("PPP configuration did not converge")
	ErrRejected    = errors.New("peer rejected a required PPP capability")
	ErrTerminated  = errors.New("peer terminated the PPP link")
	ErrKeepalive   = errors.New("PPP peer missed three keepalive replies")
	ErrNotOpen     = errors.New("PPP IPv4 link is not open")
	ErrClosed      = errors.New("PPP link is closed")
	// ErrRenegotiation requires a fresh link when network reconfiguration is unavailable.
	ErrRenegotiation = errors.New("PPP renegotiation requires a fresh link")
)

// machine tracks the two independently acknowledged directions of one protocol.
// localAck/peerAck represent Request-Sent, Ack-Received, Ack-Sent, and Opened.
// Each replacement request receives a fresh ID; timer retransmissions retain it.
type machine struct {
	protocol uint16
	id       byte
	request  []byte
	localAck bool
	peerAck  bool
	attempts int
	changes  int
	due      time.Time
	peerID   byte
	peerData []byte
	peerCode byte
	peerBody []byte
}

// engine owns mutable protocol state on the link worker, never on its reader.
type engine struct {
	config    Config
	lcp       machine
	ipcp      machine
	info      Negotiated
	ipActive  bool
	opened    bool
	deadline  time.Time
	echoDue   time.Time
	controlID byte
	echoID    byte
	echoWait  bool
	misses    int
	stopping  bool
	stopID    byte
	stopDue   time.Time
	stopTry   int
}

// newEngine initializes the default LCP offer and a bounded negotiation deadline.
func newEngine(config Config, now time.Time) *engine {
	e := &engine{config: config, deadline: now.Add(config.NegotiationTimeout)}
	e.info = Negotiated{MRU: DefaultMRU, PeerMRU: 1500, Magic: config.Magic}
	e.lcp = machine{protocol: ProtocolLCP, request: append([]byte{1, 4, 5, 74}, uint32Option(5, config.Magic)...)}
	e.ipcp.protocol = ProtocolIPCP
	return e
}

// open reports whether both directions acknowledged this protocol's current offer.
func (m *machine) open() bool { return m.localAck && m.peerAck }

// sendRequest emits a fresh offer or a byte-identical retransmission, capped across
// all changes so a peer cannot reset the retry budget with endless Nak/Rejects.
func (m *machine) sendRequest(e *engine, now time.Time, fresh bool) ([]byte, error) {
	if m.attempts >= e.config.MaxConfigure {
		return nil, ErrNegotiation
	}
	if fresh {
		m.id++
		m.localAck = false
	}
	m.attempts++
	m.due = now.Add(e.config.RetryInterval)
	return controlPacket(m.protocol, ConfigureRequest, m.id, m.request), nil
}

// beginIPCP starts address and optional DNS discovery only after LCP is open.
func (e *engine) beginIPCP(now time.Time) ([]byte, error) {
	e.ipActive = true
	e.ipcp = machine{protocol: ProtocolIPCP, request: uint32Option(3, 0)}
	if !e.config.DisableDNS {
		e.ipcp.request = append(e.ipcp.request, uint32Option(129, 0)...)
		e.ipcp.request = append(e.ipcp.request, uint32Option(131, 0)...)
	}
	return e.ipcp.sendRequest(e, now, true)
}

// advance opens the next protocol or schedules keepalive when both are negotiated.
// During termination it preserves control output without reopening either protocol.
func (e *engine) advance(now time.Time, output [][]byte) ([][]byte, error) {
	if e.stopping {
		return output, nil
	}
	if e.lcp.open() && !e.ipActive {
		packet, err := e.beginIPCP(now)
		if err != nil {
			return nil, err
		}
		output = append(output, packet)
	}
	if e.ipcp.open() && e.lcp.open() && !e.opened {
		if !usableAddress(e.info.LocalIP) {
			return nil, ErrRejected
		}
		e.opened = true
		e.deadline = time.Time{}
		e.echoDue = now.Add(e.config.EchoInterval)
	}
	return output, nil
}

// input demultiplexes bounded full-protocol packets, ignoring malformed control
// packets without responding. Unsupported protocols receive LCP Protocol-Reject.
func (e *engine) input(packet []byte, now time.Time) ([][]byte, []byte, error) {
	if len(packet) < 2 || len(packet)-2 > e.info.MRU {
		return nil, nil, nil
	}
	protocol := binary.BigEndian.Uint16(packet[:2])
	if protocol&1 == 0 || packet[0]&1 != 0 {
		return nil, nil, nil
	}
	if protocol == ProtocolIPv4 {
		if e.opened && !e.stopping && validIPv4(packet[2:]) {
			return nil, bytes.Clone(packet[2:]), nil
		}
		return nil, nil, nil
	}
	if protocol != ProtocolLCP && protocol != ProtocolIPCP {
		if !e.lcp.open() || e.stopping {
			return nil, nil, nil
		}
		return [][]byte{controlPacket(ProtocolLCP, ProtocolReject, e.nextEchoID(), e.truncate(packet))}, nil, nil
	}
	if protocol == ProtocolIPCP && (!e.lcp.open() || !e.ipActive || e.stopping) {
		return nil, nil, nil
	}
	control, err := DecodeControl(packet[2:])
	if err != nil {
		return nil, nil, nil
	}
	output, err := e.control(protocol, control, now)
	if err != nil {
		return output, nil, err
	}
	output, err = e.advance(now, output)
	return output, nil, err
}

// control applies configuration, termination, rejection, and LCP echo transitions.
func (e *engine) control(protocol uint16, c Control, now time.Time) ([][]byte, error) {
	m := &e.lcp
	if protocol == ProtocolIPCP {
		m = &e.ipcp
	}
	switch c.Code {
	case ConfigureRequest:
		if e.stopping {
			return nil, nil
		}
		return e.peerRequest(m, c, now)
	case ConfigureAck:
		if !e.stopping && c.ID == m.id && bytes.Equal(c.Data, m.request) && !m.localAck {
			m.localAck = true
			// Ack-Received has its own bounded wait for the peer direction.
			m.due = now.Add(e.config.RetryInterval)
		}
	case ConfigureNak, ConfigureReject:
		if e.stopping || c.ID != m.id || m.open() {
			return nil, nil
		}
		changed, err := e.changeOffer(m, c)
		if err != nil || !changed {
			return nil, err
		}
		packet, err := m.sendRequest(e, now, true)
		return singleton(packet), err
	case TerminateRequest:
		ack := controlPacket(protocol, TerminateAck, c.ID, e.truncate(c.Data))
		return [][]byte{ack}, ErrTerminated
	case TerminateAck:
		if e.stopping && protocol == ProtocolLCP && c.ID == e.stopID {
			return nil, ErrClosed
		}
	case CodeReject:
		if len(c.Data) < 4 {
			return nil, nil
		}
		if c.Data[0] >= ConfigureRequest && c.Data[0] <= CodeReject {
			return nil, ErrRejected
		}
		if c.Data[0] == EchoRequest && protocol == ProtocolLCP {
			return nil, ErrRejected
		}
	case ProtocolReject:
		if protocol != ProtocolLCP {
			return e.rejectCode(protocol, c), nil
		}
		if len(c.Data) >= 2 {
			rejected := binary.BigEndian.Uint16(c.Data[:2])
			if rejected == ProtocolLCP || rejected == ProtocolIPCP || rejected == ProtocolIPv4 {
				return nil, ErrRejected
			}
		}
	case EchoRequest, EchoReply:
		if protocol != ProtocolLCP {
			return e.rejectCode(protocol, c), nil
		}
		if !e.lcp.open() || len(c.Data) < 4 {
			return nil, nil
		}
		magic := binary.BigEndian.Uint32(c.Data[:4])
		if magic != e.info.PeerMagic {
			return nil, nil
		}
		if c.Code == EchoRequest {
			body := bytes.Clone(c.Data)
			binary.BigEndian.PutUint32(body[:4], e.info.Magic)
			return [][]byte{controlPacket(ProtocolLCP, EchoReply, c.ID, e.truncate(body))}, nil
		}
		if e.echoWait && c.ID == e.echoID {
			e.echoWait, e.misses = false, 0
		}
	case DiscardRequest:
		if protocol != ProtocolLCP {
			return e.rejectCode(protocol, c), nil
		}
	default:
		return e.rejectCode(protocol, c), nil
	}
	return nil, nil
}

// singleton makes an optional output list without sending a nil packet on error.
func singleton(packet []byte) [][]byte {
	if packet == nil {
		return nil
	}
	return [][]byte{packet}
}

// truncate ensures reject/echo bodies fit the peer's negotiated information MRU.
func (e *engine) truncate(body []byte) []byte {
	limit := min(e.info.PeerMRU, DefaultMRU) - 4
	return body[:min(len(body), limit)]
}

// nextEchoID allocates identifiers for unsolicited LCP diagnostic packets.
func (e *engine) nextEchoID() byte { e.controlID++; return e.controlID }

// rejectCode returns the original unsupported control packet in an LCP/IPCP
// Code-Reject, truncated as allowed by the recipient's information-field MRU.
func (e *engine) rejectCode(protocol uint16, c Control) [][]byte {
	original := controlPacket(protocol, c.Code, c.ID, c.Data)[2:]
	return [][]byte{controlPacket(protocol, CodeReject, e.nextEchoID(), e.truncate(original))}
}

// peerRequest gives Reject precedence over Nak and only Acks the original bytes.
// Repeated identical requests are replayed without resetting state or retry budgets.
func (e *engine) peerRequest(m *machine, c Control, now time.Time) ([][]byte, error) {
	options, err := DecodeOptions(c.Data)
	if err != nil {
		return nil, nil
	}
	if m.peerCode != 0 && c.ID == m.peerID && bytes.Equal(c.Data, m.peerData) {
		return [][]byte{controlPacket(m.protocol, m.peerCode, c.ID, m.peerBody)}, nil
	}
	wasOpen := m.open()
	if wasOpen && e.config.StopOnRenegotiation {
		// Fail on the serialized control worker before any new address can carry data.
		return nil, ErrRenegotiation
	}
	reject, nak, candidate := e.checkPeer(m.protocol, options)
	code, body := ConfigureAck, c.Data
	if len(reject) > 0 {
		code, body = ConfigureReject, reject
	} else if len(nak) > 0 {
		code, body = ConfigureNak, nak
	}
	m.peerAck = code == ConfigureAck
	m.peerID, m.peerData = c.ID, bytes.Clone(c.Data)
	m.peerCode, m.peerBody = code, bytes.Clone(body)
	if m.peerAck {
		e.info = candidate
	}
	output := [][]byte{controlPacket(m.protocol, code, c.ID, body)}
	if wasOpen {
		// A new offer closes the network layer until both directions reopen.
		e.opened, e.echoWait = false, false
		e.deadline = now.Add(e.config.NegotiationTimeout)
		m.attempts, m.changes = 0, 0
		if m.protocol == ProtocolLCP {
			e.ipActive = false
			e.ipcp = machine{protocol: ProtocolIPCP}
			e.info.LocalIP, e.info.PeerIP = netip.Addr{}, netip.Addr{}
			e.info.PrimaryDNS, e.info.SecondaryDNS = netip.Addr{}, netip.Addr{}
		}
		packet, err := m.sendRequest(e, now, true)
		return append(output, singleton(packet)...), err
	}
	return output, nil
}

// checkPeer validates supported options without committing partially rejected
// values. ACCM is accepted but unnecessary on this non-HDLC transport.
func (e *engine) checkPeer(protocol uint16, options []Option) ([]byte, []byte, Negotiated) {
	candidate := e.info
	var reject, nak []byte
	if protocol == ProtocolLCP {
		candidate.PeerMRU, candidate.PeerMagic = 1500, 0
	} else {
		candidate.PeerIP = netip.Addr{}
	}
	for _, option := range options {
		wire := optionBytes(option)
		if protocol == ProtocolLCP {
			switch {
			case option.Type == 1 && len(option.Data) == 2:
				mru := int(binary.BigEndian.Uint16(option.Data))
				if mru < 128 {
					nak = append(nak, 1, 4, 5, 74)
				} else {
					candidate.PeerMRU = mru
				}
			case option.Type == 2 && len(option.Data) == 4:
				// ACCM has no effect because the packet transport is not HDLC.
			case option.Type == 5 && len(option.Data) == 4:
				magic := binary.BigEndian.Uint32(option.Data)
				if magic == 0 || magic == e.info.Magic {
					nak = append(nak, uint32Option(5, differentMagic(e.info.Magic))...)
				} else {
					candidate.PeerMagic = magic
				}
			default:
				reject = append(reject, wire...)
			}
			continue
		}
		switch {
		case option.Type == 3 && len(option.Data) == 4 && usableAddress(address(option.Data)):
			candidate.PeerIP = address(option.Data)
		case (option.Type == 129 || option.Type == 131) && len(option.Data) == 4:
			if usableAddress(address(option.Data)) {
				continue
			}
			fallback := e.config.PrimaryDNS
			if option.Type == 131 {
				fallback = e.config.SecondaryDNS
			}
			if usableAddress(fallback) {
				nak = append(nak, addressOption(option.Type, fallback)...)
			} else {
				reject = append(reject, wire...)
			}
		default:
			reject = append(reject, wire...)
		}
	}
	return reject, nak, candidate
}

// changeOffer validates requested replacements in request order before updating
// the offer. A Reject must reproduce each rejected option byte for byte. Trailing
// unrequested Nak suggestions are ignored so omitted capabilities stay disabled.
func (e *engine) changeOffer(m *machine, c Control) (bool, error) {
	options, err := DecodeOptions(c.Data)
	if err != nil || len(options) == 0 {
		return false, nil
	}
	requested, err := DecodeOptions(m.request)
	if err != nil {
		return false, err
	}
	var requestedTypes [256]bool
	for _, option := range requested {
		requestedTypes[option.Type] = true
	}
	position, replacements := 0, 0
	appended := false
	for _, option := range options {
		if !requestedTypes[option.Type] && c.Code == ConfigureNak {
			// Additional suggestions may follow requested replacements, but cannot
			// enable omitted options or invalidate an otherwise usable assignment.
			appended = true
			continue
		}
		if appended {
			return false, nil
		}
		for position < len(requested) && requested[position].Type != option.Type {
			position++
		}
		if position == len(requested) || (c.Code == ConfigureReject && !bytes.Equal(optionBytes(option), optionBytes(requested[position]))) {
			return false, nil
		}
		if c.Code == ConfigureNak && !e.validNak(m.protocol, option) {
			return false, nil
		}
		position++
		replacements++
	}
	// Only the validated requested prefix participates in offer changes and budgets.
	options = options[:replacements]
	if len(options) == 0 {
		return false, nil
	}
	m.changes++
	if m.changes > e.config.MaxNak {
		return false, ErrNegotiation
	}
	updated := make([]byte, 0, len(m.request))
	for _, original := range requested {
		replacement := original
		remove := false
		for _, option := range options {
			if original.Type != option.Type {
				continue
			}
			if c.Code == ConfigureReject {
				if original.Type == 1 || (m.protocol == ProtocolIPCP && original.Type == 3) {
					return false, ErrRejected
				}
				remove = true
				if m.protocol == ProtocolLCP && original.Type == 5 {
					e.info.Magic = 0
				}
				if m.protocol == ProtocolIPCP && original.Type == 129 {
					e.info.PrimaryDNS = netip.Addr{}
				}
				if m.protocol == ProtocolIPCP && original.Type == 131 {
					e.info.SecondaryDNS = netip.Addr{}
				}
			} else {
				replacement = option
				e.applyNak(m.protocol, option)
			}
		}
		if !remove {
			updated = append(updated, optionBytes(replacement)...)
		}
	}
	m.request = updated
	return true, nil
}

// validNak verifies option widths and supported values before any state mutation.
func (e *engine) validNak(protocol uint16, option Option) bool {
	if protocol == ProtocolLCP {
		if option.Type == 1 && len(option.Data) == 2 {
			mru := int(binary.BigEndian.Uint16(option.Data))
			return mru >= 128 && mru <= DefaultMRU
		}
		return option.Type == 5 && len(option.Data) == 4 && binary.BigEndian.Uint32(option.Data) != 0 && binary.BigEndian.Uint32(option.Data) != e.info.PeerMagic
	}
	return len(option.Data) == 4 && usableAddress(address(option.Data))
}

// applyNak adopts the validated local address, receive MRU, magic, or DNS value.
func (e *engine) applyNak(protocol uint16, option Option) {
	if protocol == ProtocolLCP {
		if option.Type == 1 {
			e.info.MRU = int(binary.BigEndian.Uint16(option.Data))
		} else {
			e.info.Magic = binary.BigEndian.Uint32(option.Data)
		}
		return
	}
	switch option.Type {
	case 3:
		e.info.LocalIP = address(option.Data)
	case 129:
		e.info.PrimaryDNS = address(option.Data)
	case 131:
		e.info.SecondaryDNS = address(option.Data)
	}
}

// address converts an already validated four-byte IPv4 wire value.
func address(data []byte) netip.Addr {
	return netip.AddrFrom4([4]byte{data[0], data[1], data[2], data[3]})
}

// addressOption encodes a valid IPv4 address in an IPCP option.
func addressOption(kind byte, addr netip.Addr) []byte {
	value := addr.As4()
	return append([]byte{kind, 6}, value[:]...)
}

// usableAddress excludes unspecified, multicast, loopback, and broadcast addresses.
func usableAddress(addr netip.Addr) bool {
	return addr.Is4() && !addr.IsUnspecified() && !addr.IsMulticast() && !addr.IsLoopback() && addr != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// differentMagic deterministically avoids both zero and a reflected local magic.
func differentMagic(magic uint32) uint32 {
	value := magic ^ 0x5a5a5a5a
	if value == 0 {
		return 1
	}
	return value
}

// tick performs bounded retransmission and keepalive at injected clock deadlines.
func (e *engine) tick(now time.Time) ([][]byte, error) {
	if e.stopping {
		if now.Before(e.stopDue) {
			return nil, nil
		}
		if e.stopTry >= e.config.MaxTerminate {
			return nil, ErrClosed
		}
		e.stopTry++
		e.stopDue = now.Add(e.config.RetryInterval)
		return [][]byte{controlPacket(ProtocolLCP, TerminateRequest, e.stopID, nil)}, nil
	}
	if !e.deadline.IsZero() && !now.Before(e.deadline) {
		return nil, ErrNegotiation
	}
	if e.opened {
		if now.Before(e.echoDue) {
			return nil, nil
		}
		if e.echoWait {
			e.misses++
			if e.misses >= 3 {
				return nil, ErrKeepalive
			}
		}
		e.echoWait = true
		id := e.nextEchoID()
		e.echoID = id
		e.echoDue = now.Add(e.config.EchoInterval)
		return [][]byte{controlPacket(ProtocolLCP, EchoRequest, id, uint32Option(5, e.info.Magic)[2:])}, nil
	}
	m := &e.lcp
	if e.lcp.open() {
		m = &e.ipcp
	}
	if now.Before(m.due) {
		return nil, nil
	}
	// Ack-Received retransmits with a fresh ID and waits for both directions again.
	packet, err := m.sendRequest(e, now, m.localAck)
	return singleton(packet), err
}

// nextDeadline selects the next timer event without wall-clock polling.
func (e *engine) nextDeadline() time.Time {
	if e.stopping {
		return e.stopDue
	}
	if e.opened {
		return e.echoDue
	}
	due := e.lcp.due
	if e.lcp.open() {
		due = e.ipcp.due
	}
	if e.deadline.Before(due) {
		return e.deadline
	}
	return due
}

// stop begins a bounded LCP termination exchange and closes the IPv4 data gate.
func (e *engine) stop(now time.Time) []byte {
	e.stopping, e.opened = true, false
	e.stopID = e.nextEchoID()
	e.stopTry, e.stopDue = 1, now.Add(e.config.RetryInterval)
	return controlPacket(ProtocolLCP, TerminateRequest, e.stopID, nil)
}

// validIPv4 checks version, header length, and exact total length without parsing
// higher layers. Malformed packets never reach the interface or packet transport.
func validIPv4(packet []byte) bool {
	return len(packet) >= 20 && packet[0]>>4 == 4 && int(packet[0]&15)*4 >= 20 && int(packet[0]&15)*4 <= len(packet) && int(binary.BigEndian.Uint16(packet[2:4])) == len(packet)
}
