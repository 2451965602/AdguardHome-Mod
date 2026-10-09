package snifilter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
)

const (
	quicV1 uint32 = 1
	quicV2 uint32 = 0x6b3343cf
)

// isDoQALPN recognizes the standardized RFC 9250 identifier and the
// versioned identifiers used by DoQ drafts.  It intentionally does not match
// arbitrary identifiers that merely contain "doq".
func isDoQALPN(protocol string) bool {
	if protocol == "doq" {
		return true
	}
	if len(protocol) != len("doq-i00") || !strings.HasPrefix(protocol, "doq-i") {
		return false
	}
	return protocol[5] >= '0' && protocol[5] <= '9' && protocol[6] >= '0' && protocol[6] <= '9'
}

func hasDoQALPN(protocols []string) bool {
	for _, protocol := range protocols {
		if isDoQALPN(protocol) {
			return true
		}
	}
	return false
}

var quicV1Salt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
var quicV2Salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}

// decryptQUICInitial passively decrypts the first QUIC Initial packet in a
// datagram.  It reassembles bounded CRYPTO frames within that packet only; it
// does not retain fragments across UDP datagrams.  Incomplete data fails open
// at the caller.
func decryptQUICInitial(b []byte) (clientHelloInfo, error) {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return clientHelloInfo{}, errors.New("not a long-header QUIC Initial")
	}
	version := binary.BigEndian.Uint32(b[1:5])
	if version != quicV1 && version != quicV2 {
		return clientHelloInfo{}, errors.New("unsupported QUIC version")
	}
	off := 5
	dcidLen := int(b[off])
	off++
	if dcidLen == 0 || dcidLen > 20 || off+dcidLen+1 > len(b) {
		return clientHelloInfo{}, errors.New("invalid connection id")
	}
	dcid := b[off : off+dcidLen]
	off += dcidLen
	scidLen := int(b[off])
	off++
	if scidLen > 20 || off+scidLen > len(b) {
		return clientHelloInfo{}, errors.New("invalid source connection id")
	}
	off += scidLen
	tokenLen, n, ok := quicVarint(b[off:])
	if !ok {
		return clientHelloInfo{}, errors.New("invalid token length")
	}
	off += n
	if tokenLen > uint64(len(b)-off) {
		return clientHelloInfo{}, errors.New("truncated token")
	}
	off += int(tokenLen)
	packetLen, n, ok := quicVarint(b[off:])
	if !ok {
		return clientHelloInfo{}, errors.New("invalid packet length")
	}
	off += n
	pnOffset := off
	if packetLen < 17 || packetLen > uint64(len(b)-pnOffset) || uint64(pnOffset)+20 > uint64(len(b)) || uint64(pnOffset)+20 > uint64(pnOffset)+packetLen {
		return clientHelloInfo{}, errors.New("truncated Initial")
	}
	// The v2 packet type for Initial is 0x1, unlike v1's 0x0.
	if version == quicV2 && b[0]&0x30 != 0x10 {
		return clientHelloInfo{}, errors.New("not v2 Initial")
	}
	if version == quicV1 && b[0]&0x30 != 0 {
		return clientHelloInfo{}, errors.New("not v1 Initial")
	}
	key, iv, hp, err := quicClientKeys(version, dcid)
	if err != nil {
		return clientHelloInfo{}, err
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		return clientHelloInfo{}, err
	}
	var mask [16]byte
	block.Encrypt(mask[:], b[pnOffset+4:pnOffset+20])
	head := append([]byte(nil), b[:pnOffset]...)
	head[0] ^= mask[0] & 0x0f
	pnLen := int(head[0]&0x03) + 1
	if pnOffset+pnLen > len(b) || int(packetLen) < pnLen {
		return clientHelloInfo{}, errors.New("invalid packet number")
	}
	var pn uint64
	for i := 0; i < pnLen; i++ {
		head = append(head, b[pnOffset+i]^mask[i+1])
		pn = pn<<8 | uint64(b[pnOffset+i]^mask[i+1])
	}
	ciphertext := b[pnOffset+pnLen : pnOffset+int(packetLen)]
	block, err = aes.NewCipher(key)
	if err != nil {
		return clientHelloInfo{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return clientHelloInfo{}, err
	}
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	plain, err := aead.Open(nil, nonce, ciphertext, head)
	if err != nil {
		return clientHelloInfo{}, err
	}
	crypto, err := quicCryptoFrame(plain)
	if err != nil {
		return clientHelloInfo{}, err
	}
	handshake := append([]byte{tlsHandshakeClientHello}, make([]byte, 3)...)
	if len(crypto) < 4 {
		return clientHelloInfo{}, errors.New("incomplete CRYPTO ClientHello")
	}
	if crypto[0] != tlsHandshakeClientHello {
		return clientHelloInfo{}, errors.New("not a ClientHello")
	}
	copy(handshake[1:4], crypto[1:4])
	handshake = append(handshake, crypto[4:]...)
	return parseClientHello(handshake)
}

func quicCryptoFrame(b []byte) ([]byte, error) {
	// A ClientHello is bounded by maxHandshakeSize.  Track individual bytes so
	// multiple CRYPTO frames can arrive in any order, while rejecting gaps,
	// conflicting overlaps, and offsets that could otherwise allocate unbounded
	// memory.  This only reassembles frames within this one UDP datagram.
	const maxCryptoSize = maxHandshakeSize
	data := make([]byte, maxCryptoSize)
	seen := make([]bool, maxCryptoSize)
	var highest int
	for len(b) > 0 {
		typ, n, ok := quicVarint(b)
		if !ok {
			return nil, errors.New("invalid frame")
		}
		b = b[n:]
		switch typ {
		case 0: // PADDING
		case 1: // PING
		case 2, 3: // ACK / ACK_ECN.
			var ackErr error
			b, ackErr = skipQUICAckFrame(b, typ == 3)
			if ackErr != nil {
				return nil, ackErr
			}
		case 6: // CRYPTO
			offset, n, ok := quicVarint(b)
			if !ok {
				return nil, errors.New("invalid CRYPTO offset")
			}
			b = b[n:]
			length, n, ok := quicVarint(b)
			if !ok {
				return nil, errors.New("invalid CRYPTO length")
			}
			b = b[n:]
			if length > uint64(len(b)) || offset > maxCryptoSize || length > maxCryptoSize-offset {
				return nil, errors.New("invalid or oversized CRYPTO data")
			}
			for i, value := range b[:int(length)] {
				at := int(offset) + i
				if seen[at] && data[at] != value {
					return nil, errors.New("conflicting CRYPTO overlap")
				}
				data[at], seen[at] = value, true
				if at+1 > highest {
					highest = at + 1
				}
			}
			b = b[int(length):]
		default:
			return nil, errors.New("unsupported Initial frame")
		}
	}
	if highest == 0 {
		return nil, errors.New("missing CRYPTO frame")
	}
	for _, ok := range seen[:highest] {
		if !ok {
			return nil, errors.New("fragmented CRYPTO data")
		}
	}
	return data[:highest], nil
}

// skipQUICAckFrame validates and skips the ACK fields, including every
// acknowledged range and the optional ECN counters.
func skipQUICAckFrame(b []byte, ecn bool) ([]byte, error) {
	var rangeCount uint64
	for i := 0; i < 4; i++ { // largest acknowledged, delay, range count, first range
		v, n, ok := quicVarint(b)
		if !ok {
			return nil, errors.New("truncated ACK frame")
		}
		if i == 2 {
			rangeCount = v
		}
		b = b[n:]
	}
	if rangeCount > uint64(len(b)/2) {
		return nil, errors.New("invalid ACK range count")
	}
	for i := uint64(0); i < rangeCount; i++ {
		for range 2 { // gap, ACK range
			_, n, ok := quicVarint(b)
			if !ok {
				return nil, errors.New("truncated ACK range")
			}
			b = b[n:]
		}
	}
	if ecn {
		for i := 0; i < 3; i++ {
			_, n, ok := quicVarint(b)
			if !ok {
				return nil, errors.New("truncated ACK_ECN frame")
			}
			b = b[n:]
		}
	}
	return b, nil
}

func quicVarint(b []byte) (uint64, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	n := 1 << ((b[0] >> 6) & 3)
	if len(b) < n {
		return 0, 0, false
	}
	v := uint64(b[0] & 0x3f)
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, n, true
}

func quicClientKeys(version uint32, dcid []byte) (key, iv, hp []byte, err error) {
	salt, keyLabel, ivLabel, hpLabel := quicV1Salt, "quic key", "quic iv", "quic hp"
	if version == quicV2 {
		salt = quicV2Salt
		keyLabel, ivLabel, hpLabel = "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	initial := hkdfExtract(salt, dcid)
	secret := hkdfExpandLabel(initial, "client in", 32)
	return hkdfExpandLabel(secret, keyLabel, 16), hkdfExpandLabel(secret, ivLabel, 12), hkdfExpandLabel(secret, hpLabel, 16), nil
}

func hkdfExtract(salt, ikm []byte) []byte {
	h := hmac.New(sha256.New, salt)
	_, _ = h.Write(ikm)
	return h.Sum(nil)
}
func hkdfExpandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	if n < 0 || n > 0xffff || n > 255*sha256.Size || len(full) < 7 || len(full) > 0xff {
		return nil
	}
	// RFC 8446 §7.1 HkdfLabel: uint16 length, opaque label<7..255>,
	// opaque context<0..255>.  QUIC Initial uses an empty context.
	info := binary.BigEndian.AppendUint16(nil, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	var out, previous []byte
	for counter := byte(1); len(out) < n; counter++ {
		h := hmac.New(sha256.New, secret)
		_, _ = h.Write(previous)
		_, _ = h.Write(info)
		_, _ = h.Write([]byte{counter})
		previous = h.Sum(nil)
		out = append(out, previous...)
	}
	return out[:n]
}
