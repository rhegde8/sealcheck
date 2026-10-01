package seal

import (
	"encoding/binary"
	"errors"
	"strings"
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
			if i+4 > len(b) {
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
