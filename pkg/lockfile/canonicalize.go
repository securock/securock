package lockfile

import (
	"cmp"
	"slices"
)

func Canonicalize(doc *Document) {
	if doc == nil {
		return
	}
	slices.Sort(doc.Source.Ecosystems)
	doc.Source.Ecosystems = compactSorted(doc.Source.Ecosystems)
	slices.Sort(doc.Source.Resolvers)
	doc.Source.Resolvers = compactSorted(doc.Source.Resolvers)

	slices.SortFunc(doc.Artifacts, func(a, b Artifact) int {
		if n := cmp.Compare(a.Subject.Ecosystem, b.Subject.Ecosystem); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Subject.Name, b.Subject.Name); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Version, b.Version); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Filename, b.Filename); n != 0 {
			return n
		}
		return cmp.Compare(a.Source.Resolver, b.Source.Resolver)
	})

	for i := range doc.Artifacts {
		art := &doc.Artifacts[i]
		if art.Evidence.Malicious.State == "" {
			art.Evidence.Malicious.State = VulnUnknown
		}
		if art.Evidence.Capabilities.State == "" {
			art.Evidence.Capabilities.State = CapUnknown
		}
		if art.Evidence.Behavior.State == "" {
			art.Evidence.Behavior.State = CapUnknown
		}
		if art.Evidence.Ownership.State == "" {
			art.Evidence.Ownership.State = CapUnknown
		}
		if art.Evidence.Chain.State == "" {
			art.Evidence.Chain.State = EvidenceUnknown
		}
		slices.SortFunc(art.Evidence.Vulnerabilities.Items, func(a, b Vulnerability) int {
			return cmp.Compare(a.ID, b.ID)
		})
		slices.SortFunc(art.Evidence.Malicious.Reports, func(a, b MaliciousReport) int {
			return cmp.Compare(a.ID, b.ID)
		})
		slices.Sort(art.Evidence.Behavior.Network)
		art.Evidence.Behavior.Network = compactSorted(art.Evidence.Behavior.Network)
		if art.Evidence.Behavior.Files != nil {
			slices.Sort(art.Evidence.Behavior.Files.Read)
			art.Evidence.Behavior.Files.Read = compactSorted(art.Evidence.Behavior.Files.Read)
			slices.Sort(art.Evidence.Behavior.Files.Write)
			art.Evidence.Behavior.Files.Write = compactSorted(art.Evidence.Behavior.Files.Write)
			if len(art.Evidence.Behavior.Files.Read) == 0 && len(art.Evidence.Behavior.Files.Write) == 0 {
				art.Evidence.Behavior.Files = nil
			}
		}
		slices.Sort(art.Evidence.Behavior.Commands)
		art.Evidence.Behavior.Commands = compactSorted(art.Evidence.Behavior.Commands)
		slices.Sort(art.Evidence.Behavior.Environment)
		art.Evidence.Behavior.Environment = compactSorted(art.Evidence.Behavior.Environment)
		slices.Sort(art.Evidence.Ownership.Maintainers)
		art.Evidence.Ownership.Maintainers = compactSorted(art.Evidence.Ownership.Maintainers)
		slices.Sort(art.Trust.Reasons)
	}
}

func compactSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:0]
	var prev string
	for i, s := range in {
		if s == "" || (i > 0 && s == prev) {
			continue
		}
		out = append(out, s)
		prev = s
	}
	return out
}
