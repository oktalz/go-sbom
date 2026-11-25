package output

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/oktalz/go-sbom/packages"
)

// graphElem is a union of the SPDX 3 element fields the tests look at.
type graphElem struct {
	Type             string            `json:"type"`
	ID               string            `json:"@id"`
	SpdxID           string            `json:"spdxId"`
	CreationInfo     string            `json:"creationInfo"`
	Name             string            `json:"name"`
	SpecVersion      string            `json:"specVersion"`
	RelationshipType string            `json:"relationshipType"`
	From             string            `json:"from"`
	DataLicense      string            `json:"dataLicense"`
	PrimaryPurpose   string            `json:"software_primaryPurpose"`
	Expression       string            `json:"simplelicensing_licenseExpression"`
	To               []string          `json:"to"`
	RootElement      []string          `json:"rootElement"`
	Element          []string          `json:"element"`
	CreatedBy        []string          `json:"createdBy"`
	CreatedUsing     []string          `json:"createdUsing"`
	CustomIDToURI    []spdx3Dictionary `json:"simplelicensing_customIdToUri"`
}

type graphDoc struct {
	Context string      `json:"@context"`
	Graph   []graphElem `json:"@graph"`
}

func spdx3Graph(t *testing.T, info *packages.Info) graphDoc {
	t.Helper()
	var buf bytes.Buffer
	if err := writeSPDX3(info, &buf); err != nil {
		t.Fatal(err)
	}
	var doc graphDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	return doc
}

func byType(graph []graphElem, typ string) []graphElem {
	var out []graphElem
	for _, e := range graph {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func relationships(graph []graphElem, typ string) []graphElem {
	var out []graphElem
	for _, r := range byType(graph, "Relationship") {
		if r.RelationshipType == typ {
			out = append(out, r)
		}
	}
	return out
}

func TestWriteSPDX3Structure(t *testing.T) {
	doc := spdx3Graph(t, sampleInfo())
	graph := doc.Graph

	if doc.Context != "https://spdx.org/rdf/3.0.1/spdx-context.jsonld" {
		t.Errorf("@context = %q", doc.Context)
	}
	ci := byType(graph, "CreationInfo")
	if len(ci) != 1 || ci[0].SpecVersion != "3.0.1" || ci[0].ID != "_:creationinfo" {
		t.Fatalf("CreationInfo = %+v", ci)
	}
	for _, typ := range []string{"SoftwareAgent", "Tool", "SpdxDocument", "software_Sbom"} {
		if n := len(byType(graph, typ)); n != 1 {
			t.Errorf("%d %s elements, want 1", n, typ)
		}
	}
	pkgs := byType(graph, "software_Package")
	if len(pkgs) != 4 { // main + 3 deps
		t.Fatalf("%d packages, want 4", len(pkgs))
	}
	if pkgs[0].Name != "github.com/example/myapp" || pkgs[0].PrimaryPurpose != "application" {
		t.Errorf("first package should be the main application: %+v", pkgs[0])
	}

	// Every element except CreationInfo has a unique spdxId and points at the
	// shared CreationInfo, and every reference resolves to an element.
	ids := map[string]bool{}
	for _, e := range graph {
		if e.Type == "CreationInfo" {
			continue
		}
		if e.SpdxID == "" || ids[e.SpdxID] {
			t.Errorf("missing or duplicate spdxId in %+v", e)
		}
		ids[e.SpdxID] = true
		if e.CreationInfo != "_:creationinfo" {
			t.Errorf("element %s has creationInfo %q", e.SpdxID, e.CreationInfo)
		}
	}
	for _, e := range graph {
		refs := slices.Concat(e.To, e.RootElement, e.Element, e.CreatedBy, e.CreatedUsing)
		for _, r := range []string{e.From, e.DataLicense} {
			if r != "" {
				refs = append(refs, r)
			}
		}
		for _, r := range refs {
			if !ids[r] {
				t.Errorf("element %q references unknown element %s", e.SpdxID, r)
			}
		}
	}

	dependsOn := relationships(graph, "dependsOn")
	if len(dependsOn) != 1 || len(dependsOn[0].To) != 3 || dependsOn[0].From != pkgs[0].SpdxID {
		t.Errorf("dependsOn = %+v, want one relationship main -> 3 deps", dependsOn)
	}
}

func TestWriteSPDX3Licenses(t *testing.T) {
	info := &packages.Info{
		Main: packages.Package{Path: "example.com/app", License: "mit"},
		Deps: []packages.Package{
			{Path: "example.com/a", Version: "v1.0.0", License: "MIT"},
			{Path: "example.com/b", Version: "v1.0.0", License: "Company Proprietary"},
			{Path: "example.com/c", Version: "v1.0.0", License: "MIT OR Apache-2.0"},
			{Path: "example.com/d", Version: "v1.0.0", License: "Unknown"},
		},
	}
	graph := spdx3Graph(t, info).Graph

	exprs := map[string]graphElem{}
	for _, e := range byType(graph, "simplelicensing_LicenseExpression") {
		exprs[e.Expression] = e
	}
	for _, want := range []string{"CC0-1.0", "MIT", "LicenseRef-Company-Proprietary", "MIT OR Apache-2.0"} {
		if _, ok := exprs[want]; !ok {
			t.Errorf("missing license expression %q (have %v)", want, exprs)
		}
	}
	if len(exprs) != 4 {
		t.Errorf("%d license expressions, want 4 (MIT shared, Unknown omitted)", len(exprs))
	}
	texts := byType(graph, "simplelicensing_SimpleLicensingText")
	if len(texts) != 1 || texts[0].Name != "Company Proprietary" {
		t.Fatalf("SimpleLicensingText = %+v", texts)
	}
	custom := exprs["LicenseRef-Company-Proprietary"].CustomIDToURI
	if len(custom) != 1 || custom[0].Key != "LicenseRef-Company-Proprietary" || custom[0].Value != texts[0].SpdxID {
		t.Errorf("customIdToUri = %+v", custom)
	}
	if n := len(relationships(graph, "hasDeclaredLicense")); n != 4 { // main, a, b, c; not the Unknown one
		t.Errorf("%d hasDeclaredLicense relationships, want 4", n)
	}
}

func TestWriteSPDX3DedupesReplacedModules(t *testing.T) {
	info := &packages.Info{
		Main: packages.Package{Path: "example.com/app"},
		Deps: []packages.Package{
			{Path: "example.com/old1", Version: "v1.0.0", Replace: &packages.Package{Path: "example.com/new", Version: "v2.0.0"}},
			{Path: "example.com/old2", Version: "v1.0.0", Replace: &packages.Package{Path: "example.com/new", Version: "v2.0.0"}},
		},
	}
	if n := len(byType(spdx3Graph(t, info).Graph, "software_Package")); n != 2 {
		t.Errorf("%d packages, want 2 (main + one shared replacement)", n)
	}
}

func TestWriteSPDX3Reproducible(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	var a, b bytes.Buffer
	if err := writeSPDX3(sampleInfo(), &a); err != nil {
		t.Fatal(err)
	}
	if err := writeSPDX3(sampleInfo(), &b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("SPDX 3 output should be reproducible with SOURCE_DATE_EPOCH")
	}
	if !strings.Contains(a.String(), `"created": "2023-11-14T22:13:20Z"`) {
		t.Error("created should come from SOURCE_DATE_EPOCH")
	}
}

func TestWriteSPDX3ViaExtensionAndFormat(t *testing.T) {
	if f, err := FormatFromPath("sbom.spdx3.json"); err != nil || f != "spdx3" {
		t.Errorf("FormatFromPath(.spdx3.json) = %q, %v", f, err)
	}
	if f, err := FormatFromPath("sbom.spdx2.json"); err != nil || f != "spdx2" {
		t.Errorf("FormatFromPath(.spdx2.json) = %q, %v", f, err)
	}
	path := filepath.Join(t.TempDir(), "out.json")
	if err := Write(sampleInfo(), path, "spdx3", false); err != nil {
		t.Fatal(err)
	}
}
