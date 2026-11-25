package output

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oktalz/go-sbom/packages"
)

func TestCanonicalSPDX(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		single bool
		ok     bool
	}{
		{"MIT", "MIT", true, true},
		{"mit", "MIT", true, true},
		{"apache-2.0", "Apache-2.0", true, true},
		{"GPL-2.0", "GPL-2.0", true, true}, // deprecated, still valid
		{"GPL-2.0+", "GPL-2.0+", true, true},
		{"MIT OR Apache-2.0", "MIT OR Apache-2.0", false, true},
		{"(mit or apache-2.0) and BSD-3-Clause", "(MIT OR Apache-2.0) AND BSD-3-Clause", false, true},
		{"Apache-2.0 WITH llvm-exception", "Apache-2.0 WITH LLVM-exception", false, true},
		{"LicenseRef-Company", "LicenseRef-Company", true, true},
		{"Proprietary", "", false, false},
		{"Apache-with-LLVM-Exception", "", false, false},
		{"MIT OR", "", false, false},
		{"(MIT", "", false, false},
		{"MIT Apache-2.0", "", false, false},
		{"MIT WITH Apache-2.0", "", false, false},
		{"", "", false, false},
	}
	for _, tt := range tests {
		got, single, ok := canonicalSPDX(tt.in)
		if got != tt.want || single != tt.single || ok != tt.ok {
			t.Errorf("canonicalSPDX(%q) = (%q, %v, %v), want (%q, %v, %v)", tt.in, got, single, ok, tt.want, tt.single, tt.ok)
		}
	}
}

func TestCdxLicenses(t *testing.T) {
	tests := []struct {
		in       string
		wantID   string
		wantName string
		wantExpr string
	}{
		{in: "MIT", wantID: "MIT"},
		{in: "MIT OR Apache-2.0", wantExpr: "MIT OR Apache-2.0"},
		{in: "LicenseRef-Company", wantExpr: "LicenseRef-Company"},
		{in: "Proprietary", wantName: "Proprietary"},
	}
	for _, tt := range tests {
		got := cdxLicenses(tt.in)
		if len(got) != 1 {
			t.Fatalf("cdxLicenses(%q) = %v, want one entry", tt.in, got)
		}
		l := got[0]
		var id, name string
		if l.License != nil {
			id, name = l.License.ID, l.License.Name
		}
		if id != tt.wantID || name != tt.wantName || l.Expression != tt.wantExpr {
			t.Errorf("cdxLicenses(%q) = id %q name %q expr %q, want id %q name %q expr %q",
				tt.in, id, name, l.Expression, tt.wantID, tt.wantName, tt.wantExpr)
		}
	}
	if cdxLicenses("Unknown") != nil || cdxLicenses("") != nil {
		t.Error("Unknown/empty license should produce no CycloneDX license")
	}
}

func TestWriteSPDXLicenseRef(t *testing.T) {
	info := &packages.Info{
		Main: packages.Package{Path: "github.com/example/app", Version: "v1.0.0", License: "Company Proprietary"},
		Deps: []packages.Package{
			{Path: "github.com/a/a", Version: "v1.0.0", License: "Company Proprietary"},
			{Path: "github.com/b/b", Version: "v1.0.0", License: "mit"},
		},
	}
	var buf bytes.Buffer
	if err := writeSPDX(info, &buf); err != nil {
		t.Fatal(err)
	}
	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Packages[0].LicenseDeclared != "LicenseRef-Company-Proprietary" {
		t.Errorf("main licenseDeclared = %q", doc.Packages[0].LicenseDeclared)
	}
	if doc.Packages[2].LicenseDeclared != "MIT" {
		t.Errorf("dep licenseDeclared = %q, want canonical MIT", doc.Packages[2].LicenseDeclared)
	}
	if len(doc.ExtractedLicenses) != 1 || doc.ExtractedLicenses[0].LicenseID != "LicenseRef-Company-Proprietary" ||
		doc.ExtractedLicenses[0].Name != "Company Proprietary" || doc.ExtractedLicenses[0].ExtractedText == "" {
		t.Errorf("hasExtractedLicensingInfos = %+v, want one LicenseRef-Company-Proprietary entry", doc.ExtractedLicenses)
	}
}

func TestSpdxIDAndPurlIncompatible(t *testing.T) {
	if got := spdxID("github.com/a/b", "v2.0.0+incompatible"); got != "SPDXRef-github.com-a-b-v2.0.0-incompatible" {
		t.Errorf("spdxID = %q", got)
	}
	if got := goPurl("github.com/a/b", "v2.0.0+incompatible"); got != "pkg:golang/github.com/a/b@v2.0.0%2Bincompatible" {
		t.Errorf("goPurl = %q", got)
	}
	if got := goPurl("example.com/app", ""); got != "pkg:golang/example.com/app" {
		t.Errorf("goPurl without version = %q, want no trailing @", got)
	}
	if got := goPurl("../fork", ""); got != "" {
		t.Errorf("goPurl(local dir) = %q, want empty", got)
	}
}

func TestSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	var buf bytes.Buffer
	if err := writeCycloneDX(sampleInfo(), &buf); err != nil {
		t.Fatal(err)
	}
	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	if bom.Metadata.Timestamp != "2023-11-14T22:13:20Z" {
		t.Errorf("timestamp = %q, want SOURCE_DATE_EPOCH time", bom.Metadata.Timestamp)
	}

	// Same input + same epoch -> byte-identical output.
	var again bytes.Buffer
	if err := writeCycloneDX(sampleInfo(), &again); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), again.Bytes()) {
		t.Error("CycloneDX output should be reproducible with SOURCE_DATE_EPOCH")
	}
}

func TestCycloneDXSerialAndRefs(t *testing.T) {
	var buf bytes.Buffer
	if err := writeCycloneDX(sampleInfo(), &buf); err != nil {
		t.Fatal(err)
	}
	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") || bom.Version != 1 {
		t.Errorf("serialNumber = %q, version = %d", bom.SerialNumber, bom.Version)
	}
	for _, c := range bom.Components {
		if c.BOMRef != c.Purl {
			t.Errorf("component %s bom-ref = %q, want purl", c.Name, c.BOMRef)
		}
	}
}

func TestWriteUnsupportedFormatCreatesNoFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.xml")
	if err := Write(sampleInfo(), path, "", false); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("unsupported format should not create %s", path)
	}
}

func TestFormatFromPath(t *testing.T) {
	tests := map[string]string{
		"a.txt": "text", "a.CSV": "csv", "a.yml": "yaml", "a.yaml": "yaml",
		"a.json": "json", "a.cyclonedx.json": "cyclonedx", "a.spdx.json": "spdx", "a.SPDX2.json": "spdx2", "a.spdx3.json": "spdx3",
	}
	for path, want := range tests {
		got, err := FormatFromPath(path)
		if err != nil || got != want {
			t.Errorf("FormatFromPath(%q) = %q, %v; want %q", path, got, err, want)
		}
		if !IsFormat(got) {
			t.Errorf("FormatFromPath(%q) returned %q, which IsFormat rejects", path, got)
		}
	}
	if _, err := FormatFromPath("a.xml"); err == nil {
		t.Error("FormatFromPath(a.xml) should fail")
	}
}

func TestResolveFormatSPDXVersion(t *testing.T) {
	tests := []struct {
		path, format, version, want string
		wantErr                     bool
	}{
		{path: "sbom.spdx.json", want: "spdx2"}, // default version
		{path: "sbom.spdx.json", version: "3", want: "spdx3"},
		{path: "sbom.SPDX.json", version: "3.0.1", want: "spdx3"},
		{format: "spdx", version: "2.3", want: "spdx2"},
		{format: "spdx", version: "3.0", want: "spdx3"},
		{path: "sbom.spdx2.json", version: "3", want: "spdx2"}, // explicit extension wins
		{path: "sbom.spdx3.json", version: "2", want: "spdx3"},
		{path: "out.json", format: "spdx3", version: "2", want: "spdx3"},
		{path: "sbom.cyclonedx.json", version: "3", want: "cyclonedx"},
		{format: "spdx", version: "4", wantErr: true},
		{path: "a.xml", wantErr: true},
		{want: ""}, // stdout text
	}
	for _, tt := range tests {
		got, err := ResolveFormat(tt.path, tt.format, tt.version)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ResolveFormat(%q, %q, %q) = %q, %v; want %q (err %v)", tt.path, tt.format, tt.version, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestWriteSPDXExtensionDefaultsTo23(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbom.spdx.json")
	if err := Write(sampleInfo(), path, "", false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"spdxVersion": "SPDX-2.3"`) {
		t.Error(".spdx.json written by Write should be SPDX 2.3")
	}
}
