// Package exceptions defines the file that records findings a team has accepted.
//
// An exception never changes securock.lock or the trust evaluation. It only
// suppresses a finding in reports, for a stated reason, until a date.
package exceptions

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion = 1

	// DefaultPath is where the exceptions file lives, relative to the project root.
	DefaultPath = ".securock/exceptions.yaml"

	// DateLayout is the format of Exception.Expires.
	DateLayout = "2006-01-02"
)

type Document struct {
	Version    int         `json:"version" yaml:"version"`
	Exceptions []Exception `json:"exceptions" yaml:"exceptions"`
}

type Exception struct {
	// ID is the finding ID to accept, such as known-vulnerability:GHSA-xxxx or capability:network.
	ID string `json:"id" yaml:"id"`
	// Subject limits the exception to one package. It is either a full artifact
	// (npm:lodash@4.17.20) or a package at any version (npm:lodash). Empty matches every package.
	Subject  string `json:"subject,omitempty" yaml:"subject,omitempty"`
	Reason   string `json:"reason" yaml:"reason"`
	Approver string `json:"approver,omitempty" yaml:"approver,omitempty"`
	// Expires is the last day the exception applies, as YYYY-MM-DD in UTC.
	Expires string `json:"expires" yaml:"expires"`
	// Justification, for a known-vulnerability exception, says the package is not
	// affected rather than that the risk is accepted. It is one of the OpenVEX
	// justifications and shapes the VEX document: Reason becomes the impact statement.
	Justification string `json:"justification,omitempty" yaml:"justification,omitempty"`
}

// Justifications are the reasons a vulnerability can be recorded as not affecting a product.
var Justifications = []string{
	"component_not_present",
	"vulnerable_code_not_present",
	"vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary",
	"inline_mitigations_already_exist",
}

// VulnerabilityPrefix starts the ID of an exception for a known vulnerability; the rest is
// the advisory ID.
const VulnerabilityPrefix = "known-vulnerability:"

func (e Exception) key() string {
	return e.ID + "\x00" + e.Subject
}

// Same reports whether two exceptions cover the same finding and package.
func (e Exception) Same(other Exception) bool {
	return e.key() == other.key()
}

// ExpiresAt is the instant the exception stops applying: the end of its Expires day.
func (e Exception) ExpiresAt() (time.Time, error) {
	day, err := time.Parse(DateLayout, e.Expires)
	if err != nil {
		return time.Time{}, fmt.Errorf("expires %q is not a YYYY-MM-DD date", e.Expires)
	}
	return day.AddDate(0, 0, 1), nil
}

// Expired reports whether the exception no longer applies at now.
// An exception with an unreadable date is treated as expired.
func (e Exception) Expired(now time.Time) bool {
	end, err := e.ExpiresAt()
	return err != nil || !now.UTC().Before(end)
}

// Matches reports whether the exception covers a finding with this ID and subject.
func (e Exception) Matches(id, subject string) bool {
	if e.ID != id {
		return false
	}
	switch {
	case e.Subject == "", e.Subject == subject:
		return true
	case strings.Contains(e.Subject, "@"):
		return false
	}
	return strings.HasPrefix(subject, e.Subject+"@")
}

func Validate(doc Document) error {
	if doc.Version != SchemaVersion {
		return fmt.Errorf("unsupported exceptions version %d", doc.Version)
	}
	seen := map[string]bool{}
	for i, e := range doc.Exceptions {
		where := fmt.Sprintf("exceptions[%d]", i)
		switch {
		case strings.TrimSpace(e.ID) == "" || strings.ContainsAny(e.ID, " \t\n"):
			return fmt.Errorf("%s: id must be a finding ID without spaces", where)
		case strings.TrimSpace(e.Reason) == "":
			return fmt.Errorf("%s (%s): reason is required", where, e.ID)
		case e.Expires == "":
			return fmt.Errorf("%s (%s): expires is required", where, e.ID)
		}
		if _, err := e.ExpiresAt(); err != nil {
			return fmt.Errorf("%s (%s): %w", where, e.ID, err)
		}
		if e.Justification != "" {
			if !strings.HasPrefix(e.ID, VulnerabilityPrefix) {
				return fmt.Errorf("%s (%s): justification only applies to known-vulnerability exceptions", where, e.ID)
			}
			if !slices.Contains(Justifications, e.Justification) {
				return fmt.Errorf("%s (%s): unknown justification %q", where, e.ID, e.Justification)
			}
		}
		if seen[e.key()] {
			return fmt.Errorf("%s: duplicate exception for %s", where, e.ID)
		}
		seen[e.key()] = true
	}
	return nil
}

// Canonicalize orders exceptions so the file is stable under repeated edits.
func Canonicalize(doc Document) Document {
	out := Document{Version: doc.Version, Exceptions: append([]Exception{}, doc.Exceptions...)}
	sort.SliceStable(out.Exceptions, func(i, j int) bool {
		a, b := out.Exceptions[i], out.Exceptions[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Subject < b.Subject
	})
	return out
}
