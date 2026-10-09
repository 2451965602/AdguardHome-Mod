package snifilter

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSniffSNI tests the parsing of the ClientHello messages of a real TLS
// client.
func TestSniffSNI(t *testing.T) {
	t.Parallel()

	const serverName = "ads.example.com"

	hello := captureClientHello(t, serverName)
	require.NotEmpty(t, hello)

	t.Run("complete", func(t *testing.T) {
		t.Parallel()

		name, err := sniffSNI(hello)
		require.NoError(t, err)
		assert.Equal(t, serverName, name)
	})

	t.Run("partial", func(t *testing.T) {
		t.Parallel()

		for i := 1; i < len(hello); i++ {
			name, err := sniffSNI(hello[:i])
			require.ErrorIsf(t, err, errNeedMore, "prefix of length %d", i)
			assert.Emptyf(t, name, "prefix of length %d", i)
		}
	})

	t.Run("split_into_records", func(t *testing.T) {
		t.Parallel()

		// The handshake message of the ClientHello is in the payload of the
		// only record, so split it into two to make sure that the handshake
		// data of the records is accumulated.
		handshake := hello[tlsRecordHeaderLen:]
		mid := len(handshake) / 2

		split := make([]byte, 0, len(hello)+tlsRecordHeaderLen)
		split = appendTLSRecord(split, handshake[:mid])
		split = appendTLSRecord(split, handshake[mid:])

		name, err := sniffSNI(split)
		require.NoError(t, err)
		assert.Equal(t, serverName, name)
	})

	t.Run("no_sni", func(t *testing.T) {
		t.Parallel()

		name, err := sniffSNI(captureClientHello(t, ""))
		require.NoError(t, err)
		assert.Empty(t, name)
	})

	t.Run("not_tls", func(t *testing.T) {
		t.Parallel()

		name, err := sniffSNI([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		require.ErrorIs(t, err, errNotTLS)
		assert.Empty(t, name)
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		name, err := sniffSNI(nil)
		require.ErrorIs(t, err, errNeedMore)
		assert.Empty(t, name)
	})
}

func TestParseClientHelloMetadata(t *testing.T) {
	t.Parallel()
	data := testClientHello([]byte("example.test"), []string{"h3", "doq"}, true)
	info, err := sniffClientHello(appendTLSRecord(nil, data))
	require.NoError(t, err)
	assert.Equal(t, "example.test", info.serverName)
	assert.Equal(t, []string{"h3", "doq"}, info.alpn)
	assert.True(t, info.ech)
}

// testClientHello creates a minimal TLS ClientHello handshake for parser tests.
func testClientHello(host []byte, alpn []string, ech bool) []byte {
	var extensions []byte
	if host != nil {
		name := append([]byte{tlsSNINameHostName}, byte(len(host)>>8), byte(len(host)))
		name = append(name, host...)
		sni := append([]byte{byte(len(name) >> 8), byte(len(name))}, name...)
		extensions = appendTLSFixtureExtension(extensions, tlsExtServerName, sni)
	}
	if alpn != nil {
		var protocols []byte
		for _, p := range alpn {
			protocols = append(protocols, byte(len(p)))
			protocols = append(protocols, p...)
		}
		payload := append([]byte{byte(len(protocols) >> 8), byte(len(protocols))}, protocols...)
		extensions = appendTLSFixtureExtension(extensions, tlsExtALPN, payload)
	}
	if ech {
		extensions = appendTLSFixtureExtension(extensions, tlsExtECH, []byte{0, 1, 2})
	}
	body := make([]byte, 34)
	body[0], body[1] = 3, 3
	body = append(body, 0)                // session id
	body = append(body, 0, 2, 0x13, 0x01) // cipher suite
	body = append(body, 1, 0)             // compression
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	return append([]byte{tlsHandshakeClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
}

func appendTLSFixtureExtension(b []byte, typ int, data []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(typ))
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// TestSniffSNI_badData tests the parsing of the malformed ClientHello
// messages.
func TestSniffSNI_badData(t *testing.T) {
	t.Parallel()

	hello := captureClientHello(t, "example.com")
	require.NotEmpty(t, hello)

	testCases := []struct {
		wantErr error
		name    string
		data    []byte
	}{{
		wantErr: errNeedMore,
		name:    "truncated_handshake",
		data:    hello[:len(hello)-10],
	}, {
		wantErr: errNeedMore,
		name:    "truncated_record_header",
		data:    hello[:tlsRecordHeaderLen-1],
	}, {
		wantErr: errNotTLS,
		name:    "bad_record_type",
		data:    withByte(hello, 0, 0x17),
	}, {
		wantErr: errNotTLS,
		name:    "bad_record_version",
		data:    withByte(hello, 1, 0x02),
	}, {
		wantErr: errNotTLS,
		name:    "bad_handshake_type",
		data:    withByte(hello, tlsRecordHeaderLen, 0x02),
	}, {
		wantErr: errNeedMore,
		name:    "filled_handshake_len",
		// Pretend that the handshake message is longer than it is.
		data: withByte(hello, tlsRecordHeaderLen+1, 0xff),
	}, {
		wantErr: errNotTLS,
		name:    "too_long_record",
		data:    withByte(withByte(hello, 3, 0xff), 4, 0xff),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			name, err := sniffSNI(tc.data)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.wantErr), "got %v", err)
			assert.Empty(t, name)
		})
	}
}

// withByte returns a copy of b with the byte at i replaced by v.
func withByte(b []byte, i int, v byte) (res []byte) {
	res = make([]byte, len(b))
	copy(res, b)
	res[i] = v

	return res
}

// appendTLSRecord appends a handshake record with payload to b.
func appendTLSRecord(b, payload []byte) (res []byte) {
	res = append(b, tlsRecordHandshake, 0x03, 0x01)
	res = append(res, byte(len(payload)>>8), byte(len(payload)))

	return append(res, payload...)
}

// captureClientHello returns the ClientHello sent by a real TLS client that
// uses serverName.  An empty serverName means that no server name is sent.
func captureClientHello(t *testing.T, serverName string) (hello []byte) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	testutil.CleanupAndRequireSuccess(t, l.Close)

	helloCh := make(chan []byte, 1)
	go func() {
		helloCh <- readClientHelloRecord(l)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)

	// The peer of this connection never answers, so the handshake always
	// fails.  Only the ClientHello is needed.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	_ = tlsConn.HandshakeContext(testutil.ContextWithTimeout(t, testTimeout))
	_ = tlsConn.Close()

	return <-helloCh
}

// readClientHelloRecord accepts a single connection from l and returns the
// first TLS record sent over it.
func readClientHelloRecord(l net.Listener) (rec []byte) {
	conn, err := l.Accept()
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	header := make([]byte, tlsRecordHeaderLen)
	_, err = io.ReadFull(conn, header)
	if err != nil {
		return nil
	}

	payload := make([]byte, binary.BigEndian.Uint16(header[3:5]))
	_, err = io.ReadFull(conn, payload)
	if err != nil {
		return nil
	}

	return append(header, payload...)
}
