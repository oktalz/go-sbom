package image

import (
	"context"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktalz/go-sbom/packages"
)

// rpmFixture returns a real rpm database from go-rpmdb's test data.
// The module is pinned by go.sum, so a missing fixture fails instead of skipping.
func rpmFixture(t *testing.T, name string) []byte {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/knqyf263/go-rpmdb").Output()
	if err != nil {
		t.Fatalf("locating go-rpmdb: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(out)), "pkg", "testdata", filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// rpmImage reads an archive with the given rpm database files and os-release.
func rpmImage(t *testing.T, osRelease string, dbs map[string][]byte) *packages.Info {
	t.Helper()
	files := map[string][]byte{"/etc/os-release": []byte(osRelease)}
	maps.Copy(files, dbs)
	layer, err := testimageLayer(files)
	if err != nil {
		t.Fatal(err)
	}
	info, err := Read(context.Background(), "", writeArchive(t, layer, "test/rpm:1"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func countType(info *packages.Info, typ string) int {
	n := 0
	for _, d := range info.Deps {
		if d.Type == typ {
			n++
		}
	}
	return n
}

func TestReadRPMFormats(t *testing.T) {
	tests := []struct {
		name, fixture, path, osRelease string
		want                           int
	}{
		{"NDB", "sle15-bci/Packages.db", "/usr/lib/sysimage/rpm/Packages.db", "ID=sles\nVERSION_ID=15.3\n", 35},
		{"SQLite", "fedora35/rpmdb.sqlite", "/usr/lib/sysimage/rpm/rpmdb.sqlite", "ID=fedora\nVERSION_ID=35\n", 137},
		{"BerkeleyDB", "centos5-plain/Packages", "/var/lib/rpm/Packages", "ID=centos\nVERSION_ID=5\n", 110},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := rpmImage(t, tt.osRelease, map[string][]byte{tt.path: rpmFixture(t, tt.fixture)})
			if got := countType(info, packages.TypeRPM); got != tt.want {
				t.Errorf("%d rpm packages, want %d", got, tt.want)
			}
			if find(info, packages.TypeRPM, "gpg-pubkey") != nil {
				t.Error("gpg-pubkey listed as a package")
			}
			for _, d := range info.Deps {
				if d.Version == "" || d.Arch == "" || d.Namespace == "" || d.Distro == "" {
					t.Errorf("incomplete package %+v", d)
					break
				}
			}
		})
	}
}

func TestReadRPMEpochAndLicense(t *testing.T) {
	info := rpmImage(t, "ID=fedora\nVERSION_ID=35\n", map[string][]byte{
		"/usr/lib/sysimage/rpm/rpmdb.sqlite": rpmFixture(t, "fedora35/rpmdb.sqlite"),
	})
	epochs, mapped := 0, 0
	for _, d := range info.Deps {
		if strings.Contains(d.Version, ":") {
			epochs++
		}
		if strings.Contains(d.License, "GPLv") || strings.Contains(d.License, "ASL 2.0") {
			t.Errorf("%s: old license name left: %q", d.Path, d.License)
		}
		if strings.Contains(d.License, "-or-later") {
			mapped++
		}
	}
	if epochs == 0 || mapped == 0 {
		t.Errorf("%d versions with an epoch, %d mapped licenses; want both", epochs, mapped)
	}
}

func TestReadRPMPrefersCurrentDatabase(t *testing.T) {
	info := rpmImage(t, "ID=fedora\nVERSION_ID=35\n", map[string][]byte{
		"/usr/lib/sysimage/rpm/rpmdb.sqlite": rpmFixture(t, "fedora35/rpmdb.sqlite"),
		"/var/lib/rpm/Packages":              rpmFixture(t, "centos5-plain/Packages"), // stale
	})
	if got := countType(info, packages.TypeRPM); got != 137 {
		t.Errorf("%d rpm packages, want only the 137 of the SQLite database", got)
	}
}

func TestReadRPMCorrupt(t *testing.T) {
	layer, err := testimageLayer(map[string][]byte{"/var/lib/rpm/rpmdb.sqlite": []byte("SQLite format 3\x00 but broken")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Read(context.Background(), "", writeArchive(t, layer, "test/bad:1"), Options{}); err == nil ||
		!strings.Contains(err.Error(), "rpm database") {
		t.Errorf("err = %v, want an rpm database error", err)
	}
}

func TestReadRPMTempCleanup(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	rpmImage(t, "ID=sles\nVERSION_ID=15\n", map[string][]byte{"/var/lib/rpm/Packages.db": rpmFixture(t, "sle15-bci/Packages.db")})
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "go-sbom-rpm-") {
			t.Errorf("temp directory %s left behind", e.Name())
		}
	}
}

func TestIsRPMFile(t *testing.T) {
	for p, want := range map[string]bool{
		"/var/lib/rpm/Packages":                  true,
		"/var/lib/rpm/Packages.db":               true,
		"/usr/lib/sysimage/rpm/rpmdb.sqlite":     true,
		"/usr/lib/sysimage/rpm/rpmdb.sqlite-wal": true,
		"/usr/lib/sysimage/rpm/rpmdb.sqlite-shm": false,
		"/usr/share/rpm/Packages":                true,
		"/var/lib/rpm/Index.db":                  false,
		"/var/lib/rpm/sub/Packages":              false,
		"/srv/rpm/Packages":                      false,
	} {
		if got := isRPMFile(p); got != want {
			t.Errorf("isRPMFile(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestRPMLicense(t *testing.T) {
	for in, want := range map[string]string{
		"GPLv2+":                         "GPL-2.0-or-later",
		"LGPLv2+ and MIT":                "LGPL-2.0-or-later AND MIT",
		"ASL 2.0":                        "Apache-2.0",
		"GPLv3+ or ASL 2.0":              "GPL-3.0-or-later OR Apache-2.0",
		"LGPLv2.1":                       "LGPL-2.1-only",
		"GPL+ or Artistic":               "GPL-1.0-or-later OR Artistic",
		"MPLv2.0":                        "MPL-2.0",
		"BSD":                            "BSD",
		"Public Domain":                  "Public Domain",
		"MIT OR Apache-2.0":              "MIT OR Apache-2.0",
		"GPL-2.0-or-later":               "GPL-2.0-or-later",
		"(GPLv2+ or LGPLv3+) and GPLv3+": "(GPL-2.0-or-later OR LGPL-3.0-or-later) AND GPL-3.0-or-later",
	} {
		if got := rpmLicense(in); got != want {
			t.Errorf("rpmLicense(%q) = %q, want %q", in, got, want)
		}
	}
}
