// Command malformed_clienthello_transcript performs a transcript-faithful TLS 1.3 test.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type captureConn struct {
	net.Conn
	firstRecord []byte
	checked     bool
	delta       int
}

func (c *captureConn) Write(p []byte) (int, error) {
	if !c.checked {
		c.firstRecord = append(c.firstRecord, p...)
		if len(c.firstRecord) >= 5 {
			recordSize := 5 + int(binary.BigEndian.Uint16(c.firstRecord[3:5]))
			if len(c.firstRecord) >= recordSize && recordSize >= 9 {
				record := c.firstRecord[:recordSize]
				if record[0] == 22 && record[5] == 1 {
					recordLen := int(binary.BigEndian.Uint16(record[3:5]))
					innerLen := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
					c.delta = recordLen - 4 - innerLen
					c.checked = true
				}
			}
		}
	}
	return c.Conn.Write(p)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 3 || (os.Args[2] != "accept" && os.Args[2] != "reject") {
		die("usage: malformed_clienthello_transcript TARGET accept|reject")
	}
	target, err := filepath.Abs(os.Args[1])
	if err != nil {
		die("resolve target: %v", err)
	}
	nameBytes, err := os.ReadFile(filepath.Join(target, "build", "name"))
	if err != nil {
		die("read generated server name: %v", err)
	}
	name := strings.TrimSpace(string(nameBytes))
	caPEM, err := os.ReadFile(filepath.Join(target, "build", "ca.pem"))
	if err != nil {
		die("read generated test CA: %v", err)
	}
	var roots *x509.CertPool
	if len(caPEM) > 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			die("generated CA PEM could not be loaded")
		}
	}

	raw, err := net.DialTimeout("tcp", "127.0.0.1:8443", 5*time.Second)
	if err != nil {
		die("connect to local QEMU forward: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(12 * time.Second))
	captured := &captureConn{Conn: raw}
	client := tls.Client(captured, &tls.Config{
		RootCAs: roots, ServerName: name,
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	})
	err = client.Handshake()
	if os.Args[2] == "reject" {
		if err == nil {
			die("fixed image completed a malformed ClientHello handshake")
		}
		alertText := strings.ToLower(err.Error())
		if !strings.Contains(alertText, "decode error") &&
			!strings.Contains(alertText, "error decoding message") {
			die("fixed image did not reject with decode_error; handshake error: %v", err)
		}
		if !captured.checked || captured.delta != 1 {
			die("wire capture did not confirm a one-byte-short inner length (checked=%v delta=%d)",
				captured.checked, captured.delta)
		}
		fmt.Printf("PASS: fixed image rejected transcript-faithful ClientHello with decode_error; inner-length delta=%d\n", captured.delta)
		return
	}
	if err != nil {
		die("frozen image did not complete TLS 1.3 handshake: %v", err)
	}
	if !captured.checked || captured.delta != 1 {
		die("wire capture did not confirm a one-byte-short inner length (checked=%v delta=%d)",
			captured.checked, captured.delta)
	}
	fmt.Printf("PASS: frozen image completed TLS 1.3 handshake after one-byte-short ClientHello; delta=%d\n", captured.delta)

	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", name)
	if _, err := io.WriteString(client, request); err != nil {
		die("write HTTP request after malformed ClientHello: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: "GET"})
	if err != nil {
		die("read HTTP response after malformed ClientHello: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		die("read HTTP response body: %v", err)
	}
	expected, err := os.ReadFile(filepath.Join(target, "www", "index.html"))
	if err != nil {
		die("read expected local site body: %v", err)
	}
	if response.StatusCode != http.StatusOK || !bytes.Equal(body, expected) {
		die("unexpected response after malformed ClientHello: status=%d body_bytes=%d expected_bytes=%d",
			response.StatusCode, len(body), len(expected))
	}
	fmt.Printf("PASS: frozen image returned HTTP 200 and exact local site body (%d bytes)\n", len(body))
}
