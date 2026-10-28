// Local transport fixture. Generates an ephemeral TLS key; never contacts a provider.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"
)

func main() {
	// The helper randomizes ClientHello, including supported signature schemes.
	// RSA also covers TLS 1.2 profiles that do not advertise ECDSA.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture.test"}, DNSNames: []string{"fixture.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	must(err)
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	plain, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	must(err)
	ws, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	must(err)
	go func() {
		for {
			c, e := plain.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _ = c.SetDeadline(time.Now().Add(15 * time.Second)); _, _ = io.Copy(c, c) }()
		}
	}()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tcp/127.0.0.1/1194" {
			http.Error(w, "wrong path", 400)
			return
		}
		c, b, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		_, _ = b.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
		_ = b.Flush()
		echoFrames(b)
	})}
	go server.Serve(ws)
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"stealth": plain.Addr().String(), "wstunnel": ws.Addr().String()})
	select {}
}

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func echoFrames(b *bufio.ReadWriter) {
	for {
		head := make([]byte, 2)
		if _, e := io.ReadFull(b, head); e != nil {
			return
		}
		n := uint64(head[1] & 127)
		if n == 126 {
			var v uint16
			if binary.Read(b, binary.BigEndian, &v) != nil {
				return
			}
			n = uint64(v)
		} else if n == 127 {
			if binary.Read(b, binary.BigEndian, &n) != nil {
				return
			}
		}
		if n > 65536 {
			return
		}
		mask := make([]byte, 4)
		if head[1]&128 != 0 {
			if _, e := io.ReadFull(b, mask); e != nil {
				return
			}
		}
		data := make([]byte, int(n))
		if _, e := io.ReadFull(b, data); e != nil {
			return
		}
		if head[1]&128 != 0 {
			for i := range data {
				data[i] ^= mask[i%4]
			}
		}
		op := head[0] & 15
		if op == 8 {
			return
		}
		if op == 9 {
			op = 10
		}
		_ = b.WriteByte(128 | op)
		if n < 126 {
			_ = b.WriteByte(byte(n))
		} else {
			_ = b.WriteByte(126)
			_ = binary.Write(b, binary.BigEndian, uint16(n))
		}
		_, _ = b.Write(data)
		if b.Flush() != nil {
			return
		}
	}
}
