// Package blocklist stops queries for unwanted domains, such as ad and
// tracking servers, before they reach the rest of the resolver.
package blocklist

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

// maxLineLen bounds the length of a line in a list file. Real lists stay far
// below it; bufio.Scanner's default of 64 KiB would be enough too, but a
// bigger limit costs nothing and avoids surprises.
const maxLineLen = 1 << 20

// Names that appear in hosts files but must never be blocked.
var reservedNames = map[string]bool{
	"localhost":             true,
	"localhost.localdomain": true,
	"broadcasthost":         true,
	"local":                 true,
}

// A List is a set of blocked domains. A domain also blocks all its
// subdomains. A List is never modified once built, so it can be shared by
// many goroutines without a lock.
type List struct {
	domains map[string]struct{}
}

// Parse reads a list in any of these line formats:
//
//	0.0.0.0 ads.example.com tracker.example.com   (hosts file)
//	ads.example.com                               (one domain per line)
//	||ads.example.com^                            (adblock)
//
// Blank lines and comments (from # to the end of a line, or lines starting
// with !) are ignored. Lines that name no usable domain, such as localhost,
// an IP address alone, a single label like "com", or an adblock exception,
// are skipped and counted.
func Parse(r io.Reader) (*List, int, error) {
	l := &List{domains: make(map[string]struct{})}
	skipped, err := l.add(r)
	if err != nil {
		return nil, 0, err
	}
	return l, skipped, nil
}

// Load parses the files at paths and merges them into one List. It returns
// the list and the number of lines skipped across all files.
func Load(paths ...string) (*List, int, error) {
	l := &List{domains: make(map[string]struct{})}
	total := 0
	for _, path := range paths {
		skipped, err := l.addFile(path)
		if err != nil {
			return nil, 0, err
		}
		total += skipped
	}
	return l, total, nil
}

func (l *List) addFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	skipped, err := l.add(f)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	return skipped, nil
}

// add parses r and adds its domains to l. It returns the number of lines
// skipped.
func (l *List) add(r io.Reader) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, maxLineLen)
	skipped := 0
	for sc.Scan() {
		names, ok := parseLine(sc.Text())
		if !ok {
			skipped++
			continue
		}
		for _, name := range names {
			l.domains[name] = struct{}{}
		}
	}
	return skipped, sc.Err()
}

// parseLine returns the domains named on line. ok is false if the line
// should have named a domain but did not; blank and comment lines return no
// names and ok true.
func parseLine(line string) (names []string, ok bool) {
	if strings.HasPrefix(strings.TrimSpace(line), "!") {
		return nil, true // adblock comment
	}
	line, _, _ = strings.Cut(line, "#")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil, true
	}

	// Hosts format: an address followed by one or more names.
	candidates := fields
	if _, err := netip.ParseAddr(fields[0]); err == nil {
		candidates = fields[1:]
	} else if len(fields) == 1 {
		candidates = []string{fromAdblock(fields[0])}
	}

	for _, c := range candidates {
		name := normalize(c)
		if validDomain(name) && !reservedNames[name] {
			names = append(names, name)
		}
	}
	return names, len(names) > 0
}

// fromAdblock turns "||ads.example.com^" into "ads.example.com". Anything
// else, including exceptions ("@@||...") and rules with options ("$..."),
// comes back unchanged and is then rejected as not a domain.
func fromAdblock(s string) string {
	if rest, ok := strings.CutPrefix(s, "||"); ok {
		if domain, ok := strings.CutSuffix(rest, "^"); ok {
			return domain
		}
	}
	return s
}

// normalize lower-cases name and removes a trailing dot.
func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// validDomain reports whether name, already normalized, is a domain of at
// least two labels made of letters, digits, hyphens and underscores.
// Requiring two labels stops a line like "com" from blocking a whole TLD.
// IPv4 addresses look like such names, so they are rejected explicitly.
func validDomain(name string) bool {
	if len(name) == 0 || len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// Len returns the number of domains in the list.
func (l *List) Len() int { return len(l.domains) }

// Blocked reports whether name or any domain it is under is in the list: for
// a.b.example.com it checks a.b.example.com, b.example.com, example.com and
// com, in that order.
func (l *List) Blocked(name string) bool {
	name = normalize(name)
	for {
		if _, ok := l.domains[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
}
