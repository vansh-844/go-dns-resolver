package blocklist

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func mustParse(t *testing.T, text string) *List {
	t.Helper()
	l, _, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func domains(l *List) []string {
	var out []string
	for d := range l.domains {
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		text        string
		want        []string
		wantSkipped int
	}{
		{"plain domain", "ads.example.com", []string{"ads.example.com"}, 0},
		{"hosts 0.0.0.0", "0.0.0.0 ads.example.com", []string{"ads.example.com"}, 0},
		{"hosts 127.0.0.1", "127.0.0.1\tads.example.com", []string{"ads.example.com"}, 0},
		{"hosts IPv6", ":: ads.example.com", []string{"ads.example.com"}, 0},
		{"hosts several names", "0.0.0.0 a.example b.example", []string{"a.example", "b.example"}, 0},
		{"adblock", "||ads.example.com^", []string{"ads.example.com"}, 0},
		{"upper case and trailing dot", "Ads.Example.COM.", []string{"ads.example.com"}, 0},
		{"underscore", "_dmarc.example.com", []string{"_dmarc.example.com"}, 0},
		{"surrounding spaces", "   ads.example.com   ", []string{"ads.example.com"}, 0},
		{"trailing comment", "0.0.0.0 ads.example.com # an ad server", []string{"ads.example.com"}, 0},
		{"duplicates", "a.example\n0.0.0.0 a.example\n||a.example^", []string{"a.example"}, 0},

		{"blank and comment lines", "\n   \n# a comment\n! adblock comment\n", nil, 0},
		{"localhost", "127.0.0.1 localhost", nil, 1},
		{"localhost.localdomain", "127.0.0.1 localhost.localdomain", nil, 1},
		{"broadcasthost", "255.255.255.255 broadcasthost", nil, 1},
		{"address alone", "0.0.0.0", nil, 1},
		{"address as the name", "0.0.0.0 0.0.0.0", nil, 1},
		{"single label", "com", nil, 1},
		{"single label in hosts", "::1 ip6-localhost ip6-loopback", nil, 1},
		{"adblock exception", "@@||good.example.com^", nil, 1},
		{"adblock with options", "||ads.example.com^$third-party", nil, 1},
		{"adblock header", "[Adblock Plus 2.0]", nil, 1},
		{"invalid characters", "ads!.example.com", nil, 1},
		{"empty label", "ads..example.com", nil, 1},
		{"label too long", strings.Repeat("a", 64) + ".com", nil, 1},
		{"good and bad names on one line", "0.0.0.0 localhost ads.example.com", []string{"ads.example.com"}, 0},

		{
			"mixed file",
			"# StevenBlack-style header\n127.0.0.1 localhost\n0.0.0.0 0.0.0.0\n\n0.0.0.0 ads.example.com\n||tracker.example^\nplain.example\n",
			[]string{"ads.example.com", "plain.example", "tracker.example"},
			2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, skipped, err := Parse(strings.NewReader(tt.text))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := domains(l); !slices.Equal(got, tt.want) {
				t.Errorf("domains = %q, want %q", got, tt.want)
			}
			if skipped != tt.wantSkipped {
				t.Errorf("skipped = %d, want %d", skipped, tt.wantSkipped)
			}
		})
	}
}

func TestParseLongLine(t *testing.T) {
	// Longer than bufio.Scanner's default limit of 64 KiB.
	line := "0.0.0.0 ads.example.com" + strings.Repeat(" ", 100_000) + "# end"
	l := mustParse(t, line)
	if !l.Blocked("ads.example.com") {
		t.Error("domain on a long line was not added")
	}
}

func TestBlocked(t *testing.T) {
	l := mustParse(t, "example.com\nads.other.org\n")

	tests := []struct {
		name string
		want bool
	}{
		{"example.com", true},
		{"ads.example.com", true},
		{"a.b.c.example.com", true},
		{"EXAMPLE.com", true},
		{"example.com.", true},
		{"ads.other.org", true},
		{"x.ads.other.org", true},

		{"other.org", false}, // a subdomain in the list does not block its parent
		{"notexample.com", false},
		{"example.com.evil", false},
		{"com", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := l.Blocked(tt.name); got != tt.want {
			t.Errorf("Blocked(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestEmptyListBlocksNothing(t *testing.T) {
	l := mustParse(t, "")
	if l.Len() != 0 || l.Blocked("example.com") {
		t.Errorf("empty list: Len = %d, blocks example.com = %v", l.Len(), l.Blocked("example.com"))
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	a := write("a.txt", "0.0.0.0 a.example\n127.0.0.1 localhost\n")
	b := write("b.txt", "||b.example^\na.example\n")

	l, skipped, err := Load(a, b)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, want := domains(l), []string{"a.example", "b.example"}; !slices.Equal(got, want) {
		t.Errorf("domains = %q, want %q", got, want)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}

	t.Run("missing file", func(t *testing.T) {
		_, _, err := Load(a, filepath.Join(dir, "missing.txt"))
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("err = %v, want fs.ErrNotExist", err)
		}
	})

	t.Run("no files", func(t *testing.T) {
		l, _, err := Load()
		if err != nil || l.Len() != 0 {
			t.Errorf("Load() = %d domains, %v; want an empty list", l.Len(), err)
		}
	})
}
