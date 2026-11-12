// Package release binds delivered software to signed artifact and SBOM identities.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/securock/securock/internal/finding"
	"github.com/securock/securock/internal/inventory"
	"github.com/securock/securock/internal/sbom"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type Statement struct {
	Version    int    `json:"version"`
	Type       string `json:"type"`
	Product    string `json:"product"`
	Release    string `json:"release"`
	Artifact   string `json:"artifact"`
	Repository string `json:"repository"`
	Revision   string `json:"revision"`
	SBOMDigest string `json:"sbom_digest"`
}
type Envelope struct {
	Payload   string `json:"payload"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}
type Shipment struct {
	Customer    string   `json:"customer"`
	Attestation Envelope `json:"attestation"`
	SBOM        []byte   `json:"sbom"`
}
type Catalog struct {
	Version   int        `json:"version"`
	Shipments []Shipment `json:"shipments"`
}
type Advisory struct {
	ID   string `json:"id"`
	PURL string `json:"purl"`
}
type Impact struct {
	Customer string `json:"customer"`
	Product  string `json:"product"`
	Release  string `json:"release"`
	Advisory string `json:"advisory"`
	PURL     string `json:"purl"`
}
type ImpactReport struct {
	Version  int      `json:"version"`
	Affected []Impact `json:"affected"`
	Unknown  []string `json:"unknown"`
}

func Digest(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
func (s Statement) Validate() error {
	raw, e := hex.DecodeString(strings.TrimPrefix(s.Artifact, "sha256:"))
	revision, re := hex.DecodeString(s.Revision)
	sb, se := hex.DecodeString(s.SBOMDigest)
	if s.Version != 1 || s.Type != "securock.release.v1" || s.Product == "" || s.Release == "" || !strings.HasPrefix(s.Artifact, "sha256:") || e != nil || len(raw) != 32 || re != nil || len(revision) != 20 && len(revision) != 32 || s.Repository == "" || se != nil || len(sb) != 32 {
		return fmt.Errorf("invalid release statement")
	}
	return nil
}
func Sign(s Statement, bom []byte, seed []byte) (Envelope, error) {
	if len(seed) != 32 {
		return Envelope{}, fmt.Errorf("Ed25519 signing seed required")
	}
	if _, e := sbom.Parse(bom); e != nil {
		return Envelope{}, e
	}
	s.Version = 1
	s.Type = "securock.release.v1"
	s.SBOMDigest = Digest(bom)
	if e := s.Validate(); e != nil {
		return Envelope{}, e
	}
	raw, _ := json.Marshal(s)
	key := ed25519.NewKeyFromSeed(seed)
	return Envelope{base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))}, nil
}
func Verify(e Envelope, bom []byte, key ed25519.PublicKey) (Statement, error) {
	var s Statement
	if len(key) != 32 || e.PublicKey != base64.StdEncoding.EncodeToString(key) {
		return s, fmt.Errorf("untrusted release signer")
	}
	raw, err := base64.StdEncoding.DecodeString(e.Payload)
	sig, se := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || se != nil || !ed25519.Verify(key, raw, sig) || json.Unmarshal(raw, &s) != nil {
		return s, fmt.Errorf("invalid release attestation")
	}
	if err = s.Validate(); err != nil {
		return s, err
	}
	if Digest(bom) != s.SBOMDigest {
		return s, fmt.Errorf("SBOM does not match signed release")
	}
	if _, err = sbom.Parse(bom); err != nil {
		return s, err
	}
	return s, nil
}
func Register(path string, shipment Shipment, key ed25519.PublicKey) error {
	statement, e := Verify(shipment.Attestation, shipment.SBOM, key)
	if e != nil {
		return e
	}
	if shipment.Customer == "" {
		return fmt.Errorf("customer required")
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	lock := path + ".lock"
	if e = os.Mkdir(lock, 0700); e != nil {
		return fmt.Errorf("catalog is locked")
	}
	defer os.Remove(lock)
	c := Catalog{Version: 1, Shipments: []Shipment{}}
	raw, e := os.ReadFile(path)
	if e == nil {
		if json.Unmarshal(raw, &c) != nil || c.Version != 1 {
			return fmt.Errorf("invalid catalog")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	for _, old := range c.Shipments {
		s, e := Verify(old.Attestation, old.SBOM, key)
		if e != nil {
			return e
		}
		if s.Product == statement.Product && s.Release == statement.Release && s.Artifact != statement.Artifact {
			return fmt.Errorf("immutable release identity conflict")
		}
		if old.Customer == shipment.Customer && old.Attestation.Payload == shipment.Attestation.Payload {
			return nil
		}
	}
	if len(c.Shipments) >= 10000 {
		return fmt.Errorf("catalog quota")
	}
	c.Shipments = append(c.Shipments, shipment)
	slices.SortFunc(c.Shipments, func(a, b Shipment) int {
		return strings.Compare(a.Customer+a.Attestation.Payload, b.Customer+b.Attestation.Payload)
	})
	raw, e = json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), "catalog-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(raw); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func Impacts(c Catalog, advisories []Advisory, key ed25519.PublicKey) (ImpactReport, error) {
	out := ImpactReport{1, []Impact{}, []string{}}
	if c.Version != 1 {
		return out, fmt.Errorf("invalid catalog")
	}
	for _, a := range advisories {
		if a.ID == "" || !strings.HasPrefix(a.PURL, "pkg:") || !strings.Contains(a.PURL, "@") {
			return out, fmt.Errorf("advisories require exact versioned purls")
		}
	}
	for _, shipment := range c.Shipments {
		s, e := Verify(shipment.Attestation, shipment.SBOM, key)
		if e != nil {
			return out, e
		}
		bom, _ := sbom.Parse(shipment.SBOM)
		if len(bom.Entries) == 0 {
			out.Unknown = append(out.Unknown, s.Product+"/"+s.Release+": empty SBOM")
		}
		for _, entry := range bom.Entries {
			if entry.PURL == "" {
				out.Unknown = append(out.Unknown, s.Product+"/"+s.Release+": component without purl")
				continue
			}
			for _, a := range advisories {
				if a.PURL == entry.PURL {
					out.Affected = append(out.Affected, Impact{shipment.Customer, s.Product, s.Release, a.ID, a.PURL})
				}
			}
		}
	}
	slices.SortFunc(out.Affected, func(a, b Impact) int {
		return strings.Compare(a.Customer+a.Product+a.Release+a.Advisory+a.PURL, b.Customer+b.Product+b.Release+b.Advisory+b.PURL)
	})
	slices.Sort(out.Unknown)
	out.Unknown = slices.Compact(out.Unknown)
	return out, nil
}
func Link(c Catalog, r inventory.Report, key ed25519.PublicKey) (inventory.Report, finding.Report, error) {
	known := map[string]bool{}
	found := []finding.Finding{}
	original := slices.Clone(r.Nodes)
	if c.Version != 1 || r.Version != 1 {
		return r, finding.New("release", nil), fmt.Errorf("invalid catalog or inventory")
	}
	for _, shipment := range c.Shipments {
		s, e := Verify(shipment.Attestation, shipment.SBOM, key)
		if e != nil {
			return r, finding.New("release", nil), e
		}
		known[s.Artifact] = true
		for _, n := range r.Nodes {
			if n.Kind == "repository" && n.ID == s.Repository && n.Revision == s.Revision {
				image := "image:" + s.Artifact
				r.Nodes = append(r.Nodes, inventory.Node{ID: image, Kind: "image", Digest: s.Artifact})
				r.Edges = append(r.Edges, inventory.Edge{From: n.ID, To: image, Relation: "signed-build", Evidence: "verified"})
			}
		}
	}
	observed := 0
	for _, n := range original {
		if n.Kind == "image" {
			observed++
			if !known[n.Digest] {
				found = append(found, finding.Finding{ID: "release:unapproved-artifact", Severity: finding.SeverityHigh, Title: "Observed image has no approved release attestation", Subject: n.ID})
			}
		}
	}
	if observed == 0 {
		found = append(found, finding.Finding{ID: "release:deployment-incomplete", Severity: finding.SeverityHigh, Title: "No image identities were available for deployment verification"})
	}
	for _, gap := range r.Gaps {
		if strings.Contains(gap, "running image digest unknown") {
			found = append(found, finding.Finding{ID: "release:deployment-incomplete", Severity: finding.SeverityHigh, Title: "Running image identity was not established", Subject: gap})
		}
	}
	slices.SortFunc(r.Nodes, func(a, b inventory.Node) int { return strings.Compare(a.ID, b.ID) })
	r.Nodes = slices.CompactFunc(r.Nodes, func(a, b inventory.Node) bool { return a.ID == b.ID })
	slices.SortFunc(r.Edges, func(a, b inventory.Edge) int { return strings.Compare(a.From+a.To+a.Relation, b.From+b.To+b.Relation) })
	r.Edges = slices.CompactFunc(r.Edges, func(a, b inventory.Edge) bool { return a == b })
	return r, finding.New("release", found), nil
}
