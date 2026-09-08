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
		slices.SortFunc(art.Evidence.Vulnerabilities.Items, func(a, b Vulnerability) int {
			return cmp.Compare(a.ID, b.ID)
		})
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
