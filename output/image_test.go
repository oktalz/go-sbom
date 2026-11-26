package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/oktalz/go-sbom/packages"
)

const testDigest = "sha256:0123456789abcdef"

func imageInfo() *packages.Info {
	return &packages.Info{
		Main: packages.Package{Type: packages.TypeOCI, Path: "registry.example.com/team/app", Version: testDigest, Arch: "amd64"},
		Image: &packages.ImageInfo{
			Ref: "registry.example.com/team/app:1.0", Digest: testDigest, Platform: "linux/amd64",
			Distro: "debian-12", Binaries: []string{"/usr/bin/app"},
		},
		Deps: []packages.Package{
			{Path: "github.com/google/uuid", Version: "v1.6.0", License: "BSD-3-Clause"},
			{Type: packages.TypeDeb, Path: "libc6", Version: "2.36-9+deb12u8", Arch: "amd64", Namespace: "debian", Distro: "debian-12", License: "LGPL-2.1-or-later"},
			{Type: packages.TypeAPK, Path: "musl", Version: "1.2.5-r0", Arch: "x86_64", Namespace: "alpine", Distro: "alpine-3.20", License: "MIT"},
		},
	}
}

func TestPurl(t *testing.T) {
	tests := []struct {
		pkg  packages.Package
		want string
	}{
		{packages.Package{Path: "github.com/a/b", Version: "v1.0.0+incompatible"}, "pkg:golang/github.com/a/b@v1.0.0%2Bincompatible"},
		{
			packages.Package{Type: packages.TypeAPK, Path: "musl", Version: "1.2.5-r0", Arch: "x86_64", Namespace: "alpine", Distro: "alpine-3.20"},
			"pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=alpine-3.20",
		},
		{
			packages.Package{Type: packages.TypeDeb, Path: "libc6", Version: "1:2.36-9+deb12u8", Arch: "amd64", Namespace: "debian", Distro: "debian-12"},
			"pkg:deb/debian/libc6@1:2.36-9%2Bdeb12u8?arch=amd64&distro=debian-12",
		},
		{packages.Package{Type: packages.TypeDeb, Path: "tzdata"}, "pkg:deb/tzdata"},
		{
			packages.Package{Type: packages.TypeOCI, Path: "index.docker.io/library/Alpine", Version: testDigest, Arch: "arm64"},
			"pkg:oci/alpine@sha256%3A0123456789abcdef?arch=arm64&repository_url=index.docker.io/library/Alpine",
		},
		{packages.Package{Type: packages.TypeDeb, Path: "libstdc++6", Version: "12.2.0", Namespace: "debian"}, "pkg:deb/debian/libstdc%2B%2B6@12.2.0"},
		{
			packages.Package{Type: packages.TypeRPM, Path: "openssl", Version: "1:1.1.1l-2.fc35", Arch: "x86_64", Namespace: "fedora", Distro: "fedora-35"},
			"pkg:rpm/fedora/openssl@1.1.1l-2.fc35?arch=x86_64&distro=fedora-35&epoch=1",
		},
		{packages.Package{Type: packages.TypeRPM, Path: "bash", Version: "5.1.8-2.fc35", Arch: "x86_64"}, "pkg:rpm/bash@5.1.8-2.fc35?arch=x86_64"},
		{packages.Package{Type: packages.TypeDeb, Path: "libc6", Version: "1:2.36"}, "pkg:deb/libc6@1:2.36"},
		{packages.Package{Type: packages.TypeOCI, Path: "image.tar", Version: testDigest}, "pkg:oci/image.tar@sha256%3A0123456789abcdef"},
	}
	for _, tt := range tests {
		if got := purl(&tt.pkg); got != tt.want {
			t.Errorf("purl(%+v) = %q, want %q", tt.pkg, got, tt.want)
		}
	}
}

func TestPkgSPDXID(t *testing.T) {
	deb := packages.Package{Type: packages.TypeDeb, Path: "libc6", Version: "2.36"}
	if got := pkgSPDXID(&deb); got != "SPDXRef-deb-libc6-2.36" {
		t.Errorf("deb id = %q", got)
	}
	gomod := packages.Package{Path: "libc6", Version: "2.36"}
	if pkgSPDXID(&gomod) == pkgSPDXID(&deb) {
		t.Error("a Go module and an OS package of the same name share an id")
	}
}

func TestSPDXIDsUnique(t *testing.T) {
	info := imageInfo()
	info.Deps = append(info.Deps,
		packages.Package{Type: packages.TypeAPK, Path: "py3-a_b", Version: "1-r0"},
		packages.Package{Type: packages.TypeAPK, Path: "py3-a-b", Version: "1-r0"},
		packages.Package{Type: packages.TypeDeb, Path: "libc6", Version: "2.36-9+deb12u8", Arch: "i386"},
		packages.Package{Path: "example.com/old", Version: "v1.0.0", Replace: &packages.Package{Path: "github.com/google/uuid", Version: "v1.6.0"}},
	)
	var buf bytes.Buffer
	if err := writeSPDX(info, &buf); err != nil {
		t.Fatal(err)
	}
	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, p := range doc.Packages {
		if ids[p.SPDXID] {
			t.Errorf("duplicate SPDXID %s", p.SPDXID)
		}
		ids[p.SPDXID] = true
	}
	// image + uuid + libc6 amd64 + musl + py3-a_b + py3-a-b + libc6 i386; the replaced uuid is the same package
	if len(doc.Packages) != 7 {
		t.Errorf("%d packages, want 7: %v", len(doc.Packages), ids)
	}

	buf.Reset()
	if err := writeSPDX3(info, &buf); err != nil {
		t.Fatal(err)
	}
	var doc3 struct {
		Graph []spdx3TestElement `json:"@graph"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc3); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range doc3.Graph {
		if e.Type == "software_Package" {
			n++
		}
	}
	if n != 7 {
		t.Errorf("SPDX 3 has %d packages, want 7", n)
	}
}

func TestWriteImageText(t *testing.T) {
	var buf bytes.Buffer
	if err := writeText(imageInfo(), &buf, false); err != nil {
		t.Fatal(err)
	}
	out := strings.Join(strings.Fields(buf.String()), " ")
	for _, want := range []string{"Image: registry.example.com/team/app:1.0", "Digest: " + testDigest, "Platform: linux/amd64", "Distro: debian-12", "Go binary: /usr/bin/app"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Go version:") {
		t.Error("image text output has a Go version line")
	}
	if !strings.Contains(out, "LICENSE TYPE") || !strings.Contains(out, "libc6 2.36-9+deb12u8 LGPL-2.1-or-later deb") {
		t.Errorf("text output missing the TYPE column:\n%s", out)
	}
}

func TestWriteTextNoTypeColumnForGo(t *testing.T) {
	var buf bytes.Buffer
	if err := writeText(sampleInfo(), &buf, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "TYPE") {
		t.Errorf("TYPE column in Go text output:\n%s", buf.String())
	}
}

func TestWriteImageCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := writeCSV(imageInfo(), &buf, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"package,version,license,type\n", "github.com/google/uuid,v1.6.0,BSD-3-Clause,go\n", "musl,1.2.5-r0,MIT,apk\n"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("CSV missing %q:\n%s", want, buf.String())
		}
	}
}

func TestWriteImageYAML(t *testing.T) {
	var buf bytes.Buffer
	if err := writeYAML(imageInfo(), &buf, false); err != nil {
		t.Fatal(err)
	}
	want := "image:\n  ref: registry.example.com/team/app:1.0\n  digest: " + testDigest +
		"\n  platform: linux/amd64\n  distro: debian-12\n  go_binaries:\n    - /usr/bin/app\n"
	if !strings.HasPrefix(buf.String(), want) {
		t.Errorf("YAML header:\n%s\nwant prefix:\n%s", buf.String(), want)
	}
	if !strings.Contains(buf.String(), "    type: apk\n") || !strings.Contains(buf.String(), "    type: go\n") {
		t.Errorf("YAML missing type fields:\n%s", buf.String())
	}

	buf.Reset()
	if err := writeYAML(sampleInfo(), &buf, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "type:") || strings.Contains(buf.String(), "image:") {
		t.Errorf("Go YAML output has image fields:\n%s", buf.String())
	}
}

func TestWriteImageJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := writeJSON(imageInfo(), &buf, false); err != nil {
		t.Fatal(err)
	}
	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Image == nil || out.Image.Digest != testDigest || out.Image.Distro != "debian-12" || len(out.Image.Binaries) != 1 {
		t.Errorf("image = %+v", out.Image)
	}
	types := map[string]string{}
	for _, d := range out.Dependencies {
		types[d.Path] = d.Type
	}
	if types["github.com/google/uuid"] != "go" || types["libc6"] != "deb" || types["musl"] != "apk" {
		t.Errorf("types = %v", types)
	}

	buf.Reset()
	if err := writeJSON(sampleInfo(), &buf, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `"type"`) || strings.Contains(buf.String(), `"image"`) {
		t.Errorf("Go JSON output has image fields:\n%s", buf.String())
	}
}

func TestWriteImageCycloneDX(t *testing.T) {
	var buf bytes.Buffer
	if err := writeCycloneDX(imageInfo(), &buf); err != nil {
		t.Fatal(err)
	}
	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	main := bom.Metadata.Component
	if main == nil || main.Type != "container" || !strings.HasPrefix(main.Purl, "pkg:oci/app@sha256%3A") {
		t.Errorf("main component = %+v", main)
	}
	purls := map[string]bool{}
	for _, c := range bom.Components {
		purls[c.Purl] = true
	}
	for _, want := range []string{
		"pkg:golang/github.com/google/uuid@v1.6.0",
		"pkg:deb/debian/libc6@2.36-9%2Bdeb12u8?arch=amd64&distro=debian-12",
		"pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=alpine-3.20",
	} {
		if !purls[want] {
			t.Errorf("component purl %q missing; have %v", want, purls)
		}
	}
}

func TestWriteImageSPDX(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSPDX(imageInfo(), &buf); err != nil {
		t.Fatal(err)
	}
	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Packages[0].PrimaryPackagePurpose != "CONTAINER" {
		t.Errorf("main purpose = %q, want CONTAINER", doc.Packages[0].PrimaryPackagePurpose)
	}
	ids := map[string]bool{}
	for _, p := range doc.Packages {
		if ids[p.SPDXID] {
			t.Errorf("duplicate SPDXID %s", p.SPDXID)
		}
		ids[p.SPDXID] = true
	}
	if !ids["SPDXRef-deb-libc6-2.36-9-deb12u8"] || !ids["SPDXRef-apk-musl-1.2.5-r0"] {
		t.Errorf("OS package ids missing: %v", ids)
	}
	for _, r := range doc.Relationships {
		if r.RelationshipType == "DEPENDS_ON" && r.SPDXElementID != doc.Packages[0].SPDXID {
			t.Errorf("DEPENDS_ON from %s, want the image", r.SPDXElementID)
		}
	}
}

type spdx3TestElement struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Purpose string `json:"software_primaryPurpose"`
}

func TestWriteImageSPDX3(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSPDX3(imageInfo(), &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Graph []spdx3TestElement `json:"@graph"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	purposes := map[string]string{}
	for _, e := range doc.Graph {
		if e.Type == "software_Package" {
			purposes[e.Name] = e.Purpose
		}
	}
	if purposes["registry.example.com/team/app"] != "container" || purposes["libc6"] != "library" {
		t.Errorf("purposes = %v", purposes)
	}
}
