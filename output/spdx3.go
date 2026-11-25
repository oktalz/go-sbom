package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/oktalz/go-sbom/packages"
	toolversion "github.com/oktalz/go-sbom/version"
)

// SPDX 3.0.1 JSON-LD output (https://spdx.github.io/spdx-spec/v3.0.1/).
// The document is a flat @graph of elements that reference each other by
// spdxId; all elements share one blank-node CreationInfo.

const (
	spdx3SpecVersion = "3.0.1"
	spdx3Context     = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
	spdx3CreationID  = "_:creationinfo"
	toolName         = "github.com/oktalz/go-sbom"
)

type spdx3Document struct {
	Context string `json:"@context"`
	Graph   []any  `json:"@graph"`
}

type spdx3CreationInfo struct {
	ID           string   `json:"@id"`
	Type         string   `json:"type"`
	SpecVersion  string   `json:"specVersion"`
	Created      string   `json:"created"`
	CreatedBy    []string `json:"createdBy"`
	CreatedUsing []string `json:"createdUsing,omitempty"`
}

// spdx3Element holds the properties shared by every SPDX 3 element.
type spdx3Element struct {
	Type         string `json:"type"`
	SpdxID       string `json:"spdxId"`
	CreationInfo string `json:"creationInfo"`
	Name         string `json:"name,omitempty"`
}

type spdx3SpdxDocument struct {
	spdx3Element
	DataLicense        string   `json:"dataLicense,omitempty"`
	ProfileConformance []string `json:"profileConformance"`
	RootElement        []string `json:"rootElement"`
	Element            []string `json:"element,omitempty"`
}

type spdx3Sbom struct {
	spdx3Element
	RootElement []string `json:"rootElement,omitempty"`
	Element     []string `json:"element,omitempty"`
}

type spdx3Package struct {
	spdx3Element
	Version        string `json:"software_packageVersion,omitempty"`
	Purl           string `json:"software_packageUrl,omitempty"`
	PrimaryPurpose string `json:"software_primaryPurpose"`
}

type spdx3Relationship struct {
	spdx3Element
	From             string   `json:"from"`
	RelationshipType string   `json:"relationshipType"`
	To               []string `json:"to"`
}

type spdx3LicenseExpression struct {
	spdx3Element
	Expression    string            `json:"simplelicensing_licenseExpression"`
	CustomIDToURI []spdx3Dictionary `json:"simplelicensing_customIdToUri,omitempty"`
}

type spdx3Dictionary struct {
	Type  string `json:"type"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

type spdx3LicenseText struct {
	spdx3Element
	Text string `json:"simplelicensing_licenseText"`
}

// spdx3Builder accumulates graph elements with deterministic ids.
type spdx3Builder struct {
	licenses map[string]string // license expression -> element id
	ns       string
	graph    []any
	members  []string // ids of elements contained in the SBOM
	relCount int
}

func (b *spdx3Builder) id(local string) string {
	return b.ns + "#" + local
}

func (b *spdx3Builder) element(typ, local, name string) spdx3Element {
	return spdx3Element{Type: typ, SpdxID: b.id(local), CreationInfo: spdx3CreationID, Name: name}
}

func (b *spdx3Builder) add(id string, e any) {
	b.graph = append(b.graph, e)
	b.members = append(b.members, id)
}

func (b *spdx3Builder) relationship(from, typ string, to []string) {
	b.relCount++
	r := spdx3Relationship{
		spdx3Element:     b.element("Relationship", fmt.Sprintf("Relationship-%d", b.relCount), ""),
		From:             from,
		RelationshipType: typ,
		To:               to,
	}
	b.add(r.SpdxID, r)
}

// licenseElement returns the id of the LicenseExpression element for license,
// creating it (and a SimpleLicensingText for non-SPDX names) on first use.
// It returns "" for unknown licenses, which SPDX 3 expresses by omission.
func (b *spdx3Builder) licenseElement(license string) string {
	if license == "" || license == "Unknown" {
		return ""
	}
	if id, ok := b.licenses[license]; ok {
		return id
	}

	n := len(b.licenses) + 1
	expr := spdx3LicenseExpression{
		spdx3Element: b.element("simplelicensing_LicenseExpression", fmt.Sprintf("LicenseExpression-%d", n), ""),
	}
	if canonical, _, ok := canonicalSPDX(license); ok {
		expr.Expression = canonical
	} else {
		ref := licenseRef(license)
		text := spdx3LicenseText{
			spdx3Element: b.element("simplelicensing_SimpleLicensingText", fmt.Sprintf("LicenseText-%d", n), license),
			Text:         "License text not included; license identified as \"" + license + "\" by go-sbom.",
		}
		b.add(text.SpdxID, text)
		expr.Expression = ref
		expr.CustomIDToURI = []spdx3Dictionary{{Type: "DictionaryEntry", Key: ref, Value: text.SpdxID}}
	}
	b.add(expr.SpdxID, expr)
	b.licenses[license] = expr.SpdxID
	return expr.SpdxID
}

// pkg adds a software_Package with its license relationships and returns its id.
func (b *spdx3Builder) pkg(p *packages.Package, purpose string) string {
	elem := spdx3Package{
		spdx3Element:   b.element("software_Package", spdxID(p.Path, p.Version), p.Path),
		Version:        p.Version,
		Purl:           goPurl(p.Path, p.Version),
		PrimaryPurpose: purpose,
	}
	b.add(elem.SpdxID, elem)
	if lic := b.licenseElement(p.License); lic != "" {
		b.relationship(elem.SpdxID, "hasDeclaredLicense", []string{lic})
		b.relationship(elem.SpdxID, "hasConcludedLicense", []string{lic})
	}
	return elem.SpdxID
}

func writeSPDX3(info *packages.Info, w io.Writer) error {
	name := info.Main.Path
	if name == "" {
		name = "go-sbom"
	}
	b := &spdx3Builder{
		ns:       fmt.Sprintf("https://spdx.org/spdxdocs/%s-%s-spdx3", name, deterministicUUID(info)),
		licenses: map[string]string{},
	}

	agent := b.element("SoftwareAgent", "SoftwareAgent-go-sbom", toolName)
	tool := b.element("Tool", "Tool-go-sbom", toolName+"@"+toolversion.Version)
	creation := spdx3CreationInfo{
		ID:           spdx3CreationID,
		Type:         "CreationInfo",
		SpecVersion:  spdx3SpecVersion,
		Created:      sbomTime(),
		CreatedBy:    []string{agent.SpdxID},
		CreatedUsing: []string{tool.SpdxID},
	}

	var mainID string
	if info.Main.Path != "" {
		mainID = b.pkg(&info.Main, "application")
	}
	seen := map[string]bool{mainID: true}
	var deps []string
	for i := range info.Deps {
		pkg := info.Deps[i].Effective()
		id := b.id(spdxID(pkg.Path, pkg.Version))
		if seen[id] {
			continue // several modules replaced by the same one
		}
		seen[id] = true
		deps = append(deps, b.pkg(pkg, "library"))
	}
	if mainID != "" && len(deps) > 0 {
		b.relationship(mainID, "dependsOn", deps)
	}

	sbom := spdx3Sbom{
		spdx3Element: b.element("software_Sbom", "SBOM", name),
		Element:      b.members,
	}
	if mainID != "" {
		sbom.RootElement = []string{mainID}
	}
	dataLicense := spdx3LicenseExpression{
		spdx3Element: b.element("simplelicensing_LicenseExpression", "DataLicense", ""),
		Expression:   "CC0-1.0",
	}
	doc := spdx3SpdxDocument{
		spdx3Element:       b.element("SpdxDocument", "SPDXRef-DOCUMENT", name),
		DataLicense:        dataLicense.SpdxID,
		ProfileConformance: []string{"core", "software", "simpleLicensing"},
		RootElement:        []string{sbom.SpdxID},
		Element:            append([]string{agent.SpdxID, tool.SpdxID, dataLicense.SpdxID, sbom.SpdxID}, b.members...),
	}

	graph := append([]any{creation, agent, tool, doc, dataLicense, sbom}, b.graph...)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(spdx3Document{Context: spdx3Context, Graph: graph})
}
