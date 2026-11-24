package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

var hrrRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
	0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
	0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

type captureConn struct {
	net.Conn
	in  bytes.Buffer
	out bytes.Buffer
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		_, _ = c.in.Write(p[:n])
	}
	return n, err
}

func (c *captureConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		_, _ = c.out.Write(p[:n])
	}
	return n, err
}

type record struct {
	typ     byte
	payload []byte
	index   int
}

func parseRecords(raw []byte) []record {
	var out []record
	for len(raw) >= 5 {
		n := int(binary.BigEndian.Uint16(raw[3:5]))
		if n > len(raw)-5 {
			break
		}
		out = append(out, record{typ: raw[0], payload: raw[5 : 5+n], index: len(out)})
		raw = raw[5+n:]
	}
	return out
}

func countHandshake(records []record, want byte) int {
	count := 0
	for _, rec := range records {
		if rec.typ != 22 {
			continue
		}
		p := rec.payload
		for len(p) >= 4 {
			n := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
			if n > len(p)-4 {
				break
			}
			if p[0] == want {
				count++
			}
			p = p[4+n:]
		}
	}
	return count
}

func inspectServer(records []record) (hrr bool, serverHellos, serverCCS int, ccsAfterFinal bool) {
	finalServerHelloIndex := -1
	for _, rec := range records {
		if rec.typ == 20 {
			serverCCS++
			if finalServerHelloIndex >= 0 && rec.index > finalServerHelloIndex {
				ccsAfterFinal = true
			}
		}
		if rec.typ != 22 {
			continue
		}
		p := rec.payload
		for len(p) >= 4 {
			n := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
			if n > len(p)-4 {
				break
			}
			if p[0] == 2 && n >= 34 {
				serverHellos++
				random := p[6:38]
				if bytes.Equal(random, hrrRandom) {
					hrr = true
				} else {
					finalServerHelloIndex = rec.index
				}
			}
			p = p[4+n:]
		}
	}
	return
}

func main() {
	raw, err := net.DialTimeout("tcp", "127.0.0.1:8443", 5*time.Second)
	if err != nil {
		panic(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(12 * time.Second))
	capture := &captureConn{Conn: raw}
	client := tls.Client(capture, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true, // local synthetic test certificate only
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.CurveP256, tls.X25519},
	})
	if err := client.Handshake(); err != nil {
		fmt.Printf("TLS handshake error: %v\n", err)
	} else {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
		response, _ := io.ReadAll(client)
		fmt.Printf("HTTP response: %t (%d bytes)\n", bytes.Contains(response, []byte("HTTP/1.")), len(response))
	}
	outRecords := parseRecords(capture.out.Bytes())
	inRecords := parseRecords(capture.in.Bytes())
	clientHelloCount := countHandshake(outRecords, 1)
	hrr, serverHelloCount, serverCCS, ccsAfterFinal := inspectServer(inRecords)
	fmt.Printf(
		"HRR differential: client_hellos=%d, hrr=%t, server_hellos=%d, server_ccs=%d, server_ccs_after_final_serverhello=%t\n",
		clientHelloCount, hrr, serverHelloCount, serverCCS, ccsAfterFinal,
	)
	if !hrr || clientHelloCount < 2 || serverHelloCount < 2 {
		fmt.Printf("Client records: %d, server records: %d\n", len(outRecords), len(inRecords))
	}
}
