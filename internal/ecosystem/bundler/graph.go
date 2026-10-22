package bundler

import (
	"regexp"
	"strings"

	"github.com/securock/securock/internal/ecosystem/core"
)

// applyGraph records edges and scopes. Gemfile.lock lists the gems the Gemfile asks for under
// DEPENDENCIES but not their groups, so the Gemfile decides which are development-only;
// without it every direct dependency counts as runtime, which can only overstate.
func applyGraph(project string, deps []core.Dependency, needs map[string][]string, direct []string) {
	byName := map[string][]string{}
	index := map[string]int{}
	for i, dep := range deps {
		byName[dep.Name] = append(byName[dep.Name], core.Identity(dep))
		index[dep.Name+"@"+dep.Version] = i
	}
	for key, names := range needs {
		i, ok := index[key]
		if !ok {
			continue
		}
		var edges []string
		for _, name := range names {
			edges = append(edges, byName[name]...)
		}
		deps[i].DependsOn = core.UnionIdentities(deps[i].DependsOn, edges)
	}

	devOnly := developmentGems(project)
	roots := map[string]string{}
	for _, name := range direct {
		scope := core.ScopeRuntime
		if devOnly[name] {
			scope = core.ScopeDev
		}
		for _, id := range byName[name] {
			roots[id] = core.MergeScope(roots[id], scope)
		}
	}
	core.ApplyScopes(deps, roots)
}

var (
	blockStart  = regexp.MustCompile(`(?:\bdo(?:\s*\|[^|]*\|)?|^\s*(?:if|unless|case|begin|while|until)\b.*)\s*(?:#.*)?$`)
	groupBlock  = regexp.MustCompile(`^\s*group\s+(.+?)\s+do\b`)
	gemLine     = regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"](.*)$`)
	inlineGroup = regexp.MustCompile(`(?:\bgroups?:|:groups?\s*=>)\s*(\[[^\]]*\]|[:\w'"]+)`)
	groupName   = regexp.MustCompile(`:?['"]?(\w+)['"]?`)
)

// developmentGems finds the gems the Gemfile puts only in the development and test groups.
// It reads the common forms (group blocks and group: options) and anything it does not
// understand counts as runtime, so a gem is never called development-only by mistake.
func developmentGems(project string) map[string]bool {
	raw, err := core.ReadFile(core.Join(project, "Gemfile"))
	if err != nil {
		return nil
	}
	dev, runtime := map[string]bool{}, map[string]bool{}

	// Each open block is either a group (its names) or some other construct (nil).
	var stack [][]string
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			continue
		case trimmed == "end" || strings.HasPrefix(trimmed, "end "):
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if m := groupBlock.FindStringSubmatch(line); m != nil {
			stack = append(stack, groupNames(m[1]))
			continue
		}
		if m := gemLine.FindStringSubmatch(line); m != nil {
			groups := enclosingGroups(stack)
			if opt := inlineGroup.FindStringSubmatch(m[2]); opt != nil {
				groups = append(groups, groupNames(opt[1])...)
			}
			if len(groups) > 0 && onlyDevelopment(groups) {
				dev[m[1]] = true
			} else {
				runtime[m[1]] = true
			}
			continue
		}
		if blockStart.MatchString(line) && !strings.HasPrefix(trimmed, "gem ") {
			stack = append(stack, nil)
		}
	}

	for name := range runtime {
		delete(dev, name)
	}
	return dev
}

func groupNames(list string) []string {
	var out []string
	for _, m := range groupName.FindAllStringSubmatch(list, -1) {
		out = append(out, m[1])
	}
	return out
}

func enclosingGroups(stack [][]string) []string {
	var out []string
	for _, names := range stack {
		out = append(out, names...)
	}
	return out
}

func onlyDevelopment(groups []string) bool {
	for _, g := range groups {
		if g != "development" && g != "test" {
			return false
		}
	}
	return true
}
