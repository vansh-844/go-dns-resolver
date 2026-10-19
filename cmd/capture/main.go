// Command capture sends one DNS query to a real server and saves the raw
// response as hex, for use as a test fixture.
//
//	go run ./cmd/capture -name www.github.com -type A
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vansh-844/pidns/internal/dnsmessage"
)

const (
	flagRD         = 0x0100 // recursion desired
	flagTC         = 0x0200 // truncated
	flagQR         = 0x8000 // response
	ednsUDPSize    = 4096
	typeOPT        = 41
	maxResponseLen = 4096
	hexLineBytes   = 32
)

var queryTypes = map[string]dnsmessage.Type{
	"A":     dnsmessage.TypeA,
	"NS":    dnsmessage.TypeNS,
	"CNAME": dnsmessage.TypeCNAME,
	"MX":    dnsmessage.TypeMX,
	"TXT":   dnsmessage.TypeTXT,
	"AAAA":  dnsmessage.TypeAAAA,
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "capture:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		server  = flag.String("server", "1.1.1.1:53", "DNS server to query (host:port)")
		name    = flag.String("name", "example.com", "name to look up")
		typ     = flag.String("type", "A", "record type: A, NS, CNAME, MX, TXT, AAAA")
		outDir  = flag.String("out", "internal/dnsmessage/testdata", "directory to write the .hex file to")
		file    = flag.String("file", "", "output file name (default <name>_<type>.hex)")
		edns    = flag.Bool("edns", false, "add an EDNS0 OPT record to the query")
		timeout = flag.Duration("timeout", 3*time.Second, "how long to wait for the response")
	)
	flag.Parse()

	qtype, ok := queryTypes[strings.ToUpper(*typ)]
	if !ok {
		return fmt.Errorf("unknown type %q", *typ)
	}

	query := &dnsmessage.Message{
		Header: dnsmessage.Header{ID: uint16(rand.Uint32()), Flags: flagRD},
		Questions: []dnsmessage.Question{
			{Name: *name, Type: qtype, Class: dnsmessage.ClassIN},
		},
	}
	if *edns {
		// An OPT record carries the UDP payload size in its class field.
		query.Additionals = []dnsmessage.ResourceRecord{
			{Name: "", Class: ednsUDPSize, Data: dnsmessage.Unknown{RRType: typeOPT}},
		}
	}

	wire, err := query.Pack()
	if err != nil {
		return fmt.Errorf("packing query: %w", err)
	}

	resp, err := exchange(*server, wire, *timeout)
	if err != nil {
		return err
	}

	// Save before parsing, so a response our parser chokes on is still kept.
	fileName := *file
	if fileName == "" {
		fileName = fmt.Sprintf("%s_%s.hex", strings.TrimSuffix(*name, "."), strings.ToUpper(*typ))
	}
	path := filepath.Join(*outDir, fileName)
	if err := writeHex(path, resp); err != nil {
		return err
	}
	fmt.Printf("saved %d bytes to %s\n", len(resp), path)

	return summarize(query.Header.ID, resp)
}

// exchange sends query to server over UDP and returns the response.
func exchange(server string, query []byte, timeout time.Duration) ([]byte, error) {
	conn, err := net.Dial("udp", server)
	if err != nil {
		return nil, fmt.Errorf("dialing %s: %w", server, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("sending query: %w", err)
	}

	buf := make([]byte, maxResponseLen)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	return buf[:n], nil
}

// writeHex writes data as lines of hex to path, creating its directory.
func writeHex(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var sb strings.Builder
	for len(data) > 0 {
		n := min(hexLineBytes, len(data))
		sb.WriteString(hex.EncodeToString(data[:n]))
		sb.WriteByte('\n')
		data = data[n:]
	}
	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

// summarize parses resp with our own parser and prints what it found, so the
// result can be compared against `dig`.
func summarize(wantID uint16, resp []byte) error {
	m, err := dnsmessage.Unpack(resp)
	if err != nil {
		return fmt.Errorf("our parser rejected the response: %w", err)
	}
	h := m.Header
	fmt.Printf("id=%#04x (sent %#04x) response=%t truncated=%t rcode=%d\n",
		h.ID, wantID, h.Flags&flagQR != 0, h.Flags&flagTC != 0, h.Flags&0xF)
	if h.ID != wantID {
		fmt.Println("warning: response ID does not match the query")
	}
	if h.Flags&flagTC != 0 {
		fmt.Println("warning: response was truncated; it would need to be retried over TCP")
	}

	for _, q := range m.Questions {
		fmt.Printf("question:   %s %s %s\n", q.Name, q.Class, q.Type)
	}
	printRecords("answer", m.Answers)
	printRecords("authority", m.Authorities)
	printRecords("additional", m.Additionals)
	return nil
}

func printRecords(section string, rrs []dnsmessage.ResourceRecord) {
	for _, rr := range rrs {
		fmt.Printf("%-11s %s %d %s %s %+v\n", section+":", rr.Name, rr.TTL, rr.Class, rr.Type(), rr.Data)
	}
}
