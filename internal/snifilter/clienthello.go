package snifilter

import (
	"encoding/binary"
	"strings"

	"github.com/AdguardTeam/golibs/errors"
)

// TLS constants used to parse the beginning of a TLS stream.  See RFC 5246 and
// RFC 8446.
const (
	// tlsRecordHandshake is the TLS record type of the handshake protocol.
	tlsRecordHandshake = 0x16

	// tlsHandshakeClientHello is the TLS handshake type of ClientHello.
	tlsHandshakeClientHello = 0x01

	// tlsExtServerName is the number of the server_name extension.
	tlsExtServerName = 0x0000
	tlsExtALPN       = 0x0010
	tlsExtECH        = 0xfe0d

	// tlsSNINameHostName is the name type of the host names within the
	// server_name extension.
	tlsSNINameHostName = 0x00

	// tlsRecordHeaderLen is the length of a TLS record header.
	tlsRecordHeaderLen = 5

	// tlsMaxRecordLen is the maximum length of a single TLS record.  See
	// https://datatracker.ietf.org/doc/html/rfc8446#section-5.1.
	tlsMaxRecordLen = 1 << 14
)

// Errors returned by [sniffSNI].
var (
	// errNotTLS is returned when the data cannot be the beginning of a TLS
	// ClientHello.
	errNotTLS = errors.Error("not a tls client hello")

	// errNeedMore is returned when the data is a valid beginning of a TLS
	// ClientHello, but the server name is not there yet.
	errNeedMore = errors.Error("not enough data")
)

// sniffSNI extracts the server name from the beginning of a TLS stream.  data
// must contain the start of the connection, and may be incomplete.
//
// It returns errNeedMore if data is a valid beginning of a ClientHello, but
// the server name is not fully present in it yet.  It returns errNotTLS if
// data cannot belong to a ClientHello, for example when the connection carries
// another protocol.
//
// An empty name with a nil error means that the ClientHello doesn't contain a
// server name, for example when the client uses ECH or connects by an IP
// address.
type clientHelloInfo struct {
	serverName string
	alpn       []string
	ech        bool
}

func sniffSNI(data []byte) (name string, err error) {
	info, err := sniffClientHello(data)
	return info.serverName, err
}

func sniffClientHello(data []byte) (info clientHelloInfo, err error) {
	var handshake []byte

	for off := 0; ; {
		if len(data)-off < tlsRecordHeaderLen {
			return info, errNeedMore
		}

		if data[off] != tlsRecordHandshake || data[off+1] != 0x03 {
			return info, errNotTLS
		}

		recLen := int(binary.BigEndian.Uint16(data[off+3 : off+5]))
		if recLen > tlsMaxRecordLen {
			return info, errNotTLS
		}

		payload := data[off+tlsRecordHeaderLen:]
		if len(payload) > recLen {
			payload = payload[:recLen]
		}

		// A handshake message may span several records, so accumulate them.
		handshake = append(handshake, payload...)

		info, err = parseClientHello(handshake)
		switch {
		case err == nil:
			return info, nil
		case !errors.Is(err, errNeedMore):
			// Don't wrap the error, because it's informative enough as is.
			return clientHelloInfo{}, err
		case len(payload) < recLen:
			// The record itself is incomplete.
			return clientHelloInfo{}, errNeedMore
		}

		off += tlsRecordHeaderLen + recLen
	}
}

// parseClientHello extracts the server name from the handshake data in b.  b
// may contain more data than the ClientHello itself.
func parseClientHello(b []byte) (info clientHelloInfo, err error) {
	if len(b) < 4 {
		return info, errNeedMore
	}

	if b[0] != tlsHandshakeClientHello {
		return info, errNotTLS
	}

	msgLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if len(b) < 4+msgLen {
		return info, errNeedMore
	}

	// Discard the rest of the handshake stream, it can only contain the
	// messages that follow the ClientHello.
	b = b[4 : 4+msgLen]

	// Skip legacy_version (2 octets) and random (32 octets).
	off := 34
	if len(b) < off {
		return info, errNotTLS
	}

	// Skip legacy_session_id.
	if off+1 > len(b) {
		return info, errNotTLS
	}
	legacySessionIDLen := int(b[off])
	off++
	if off+legacySessionIDLen > len(b) {
		return info, errNotTLS
	}
	off += legacySessionIDLen

	// Skip cipher_suites.
	if off+2 > len(b) {
		return info, errNotTLS
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+cipherSuitesLen > len(b) {
		return info, errNotTLS
	}
	off += cipherSuitesLen

	// Skip legacy_compression_methods.
	if off+1 > len(b) {
		return info, errNotTLS
	}
	compressionLen := int(b[off])
	off++
	if off+compressionLen > len(b) {
		return info, errNotTLS
	}
	off += compressionLen

	if off == len(b) {
		// No extensions, and thus no server name.
		return info, nil
	}

	if off+2 > len(b) {
		return info, errNotTLS
	}
	extLen := int(binary.BigEndian.Uint16(b[off : off+2]))
	off += 2
	if off+extLen > len(b) {
		return info, errNotTLS
	}
	extensions := b[off : off+extLen]

	for len(extensions) >= 4 {
		extType := int(binary.BigEndian.Uint16(extensions[:2]))
		extLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		if 4+extLen > len(extensions) {
			return info, errNotTLS
		}

		switch extType {
		case tlsExtServerName:
			info.serverName, err = parseServerName(extensions[4 : 4+extLen])
			if err != nil {
				return clientHelloInfo{}, err
			}
		case tlsExtALPN:
			info.alpn, err = parseALPN(extensions[4 : 4+extLen])
			if err != nil {
				return clientHelloInfo{}, err
			}
		case tlsExtECH:
			info.ech = true
		}

		extensions = extensions[4+extLen:]
	}
	if len(extensions) != 0 {
		return info, errNotTLS
	}

	return info, nil
}

func parseALPN(b []byte) ([]string, error) {
	if len(b) < 2 {
		return nil, errNotTLS
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if n != len(b)-2 {
		return nil, errNotTLS
	}
	b = b[2:]
	var protocols []string
	for len(b) > 0 {
		l := int(b[0])
		b = b[1:]
		if l == 0 || l > len(b) {
			return nil, errNotTLS
		}
		protocols = append(protocols, string(b[:l]))
		b = b[l:]
	}
	return protocols, nil
}

// parseServerName extracts the host name from the data of the server_name
// extension.
func parseServerName(b []byte) (name string, err error) {
	if len(b) < 2 {
		return "", errNotTLS
	}

	listLen := int(binary.BigEndian.Uint16(b[:2]))
	if 2+listLen > len(b) {
		return "", errNotTLS
	}

	list := b[2 : 2+listLen]
	for len(list) >= 3 {
		nameType := list[0]
		nameLen := int(binary.BigEndian.Uint16(list[1:3]))
		if 3+nameLen > len(list) {
			return "", errNotTLS
		}

		if nameType == tlsSNINameHostName {
			// A fully-qualified name may end with a dot, which isn't a part of
			// the name itself.
			return strings.TrimSuffix(string(list[3:3+nameLen]), "."), nil
		}

		list = list[3+nameLen:]
	}

	return "", nil
}
