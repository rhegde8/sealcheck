package seal

import (
	"encoding/binary"
	"errors"
	"strings"
)

const (
	dnsTypeNS  = 2
	dnsTypeSOA = 6
)

func validZone(zone string) bool {
	zone = strings.TrimSuffix(zone, ".")
	if len(zone) < 1 || len(zone) > 100 {
		return false
	}
	for _, label := range strings.Split(zone, ".") {
		if !identifier.MatchString(label) {
			return false
		}
	}
	return true
}

func dnsQuestion(name string) ([]byte, error) {
	if len(name) > 253 {
		return nil, errors.New("DNS name too long")
	}
	b := make([]byte, 12)
	b[0] = 0x53
	b[1] = 0x43
	b[2] = 1
	b[5] = 1
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(l) < 1 || len(l) > 63 {
			return nil, errors.New("invalid label")
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0, 0, 1, 0, 1)
	return b, nil
}

// parseDNS deliberately accepts only a single uncompressed question. No recursive service.
func parseDNS(b []byte) (string, int, bool) {
	if len(b) < 12 || b[2]&0x80 != 0 || binary.BigEndian.Uint16(b[4:6]) != 1 {
		return "", 0, false
	}
	i := 12
	labels := []string{}
	for i < len(b) {
		n := int(b[i])
		i++
		if n == 0 {
			if len(labels) == 0 || i+4 > len(b) {
				return "", 0, false
			}
			return strings.ToLower(strings.Join(labels, ".")), i + 4, true
		}
		if n > 63 || i+n > len(b) || i > 253 {
			return "", 0, false
		}
		labels = append(labels, string(b[i:i+n]))
		i += n
	}
	return "", 0, false
}

// dnsResponse answers a parsed question authoritatively. Names below the zone
// get NODATA rather than NXDOMAIN: an NXDOMAIN for a minimized query such as
// <token>.<zone> makes QNAME-minimizing resolvers stop before the full canary
// name arrives (RFC 8020), hiding a leak that already happened.
func dnsResponse(question []byte, name, zone string) []byte {
	zone = strings.TrimSuffix(zone, ".")
	r := append([]byte(nil), question...)
	r[2] = 0x84 | question[2]&0x01 // response, authoritative, copy RD
	r[3] = 0
	for i := 6; i < 12; i++ {
		r[i] = 0
	}
	if name != zone && !strings.HasSuffix(name, "."+zone) {
		r[3] = 5 // REFUSED: no authority outside the controlled zone
		return r
	}
	qtype := binary.BigEndian.Uint16(question[len(question)-4:])
	switch {
	case name == zone && qtype == dnsTypeSOA:
		r[7] = 1
		r = append(r, dnsSOA(zone)...)
	case name == zone && qtype == dnsTypeNS:
		r[7] = 1
		r = append(r, dnsRecord(zone, dnsTypeNS, dnsName("ns."+zone))...)
	default:
		r[9] = 1 // NODATA with the zone SOA in the authority section
		r = append(r, dnsSOA(zone)...)
	}
	return r
}

func dnsSOA(zone string) []byte {
	rdata := append(dnsName("ns."+zone), dnsName("hostmaster."+zone)...)
	// Serial, refresh, retry, expire, and a zero negative-caching TTL.
	for _, v := range []uint32{1, 3600, 600, 86400, 0} {
		rdata = binary.BigEndian.AppendUint32(rdata, v)
	}
	return dnsRecord(zone, dnsTypeSOA, rdata)
}

func dnsRecord(owner string, rrtype uint16, rdata []byte) []byte {
	b := dnsName(owner)
	b = binary.BigEndian.AppendUint16(b, rrtype)
	b = binary.BigEndian.AppendUint16(b, 1) // IN
	b = binary.BigEndian.AppendUint32(b, 0) // TTL
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

// dnsName encodes a validated zone-relative name without compression.
func dnsName(name string) []byte {
	b := []byte{}
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func dnsCanary(name, zone string) (Event, bool) {
	name = strings.TrimSuffix(name, ".")
	zone = strings.TrimSuffix(zone, ".")
	if !strings.HasSuffix(name, "."+zone) {
		return Event{}, false
	}
	parts := strings.Split(strings.TrimSuffix(name, "."+zone), ".")
	if len(parts) != 4 {
		return Event{}, false
	}
	return ParseCanary([]byte(strings.Join(parts, ":")))
}
