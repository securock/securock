package evidence

import (
	"encoding/json"
	"strings"
	"time"
	"unicode"

	"github.com/securock/securock/pkg/lockfile"
)

// clip makes registry-supplied text safe to store: one line, bounded length.
func clip(s string) string {
	s = strings.Join(strings.FieldsFunc(s, unicode.IsSpace), " ")
	if len(s) <= lockfile.MaxHealthText {
		return s
	}
	runes := []rune(s)
	for len(string(runes)) > lockfile.MaxHealthText {
		runes = runes[:len(runes)-1]
	}
	return string(runes)
}

// day formats a registry timestamp as YYYY-MM-DD, or "" when it cannot be read.
func day(stamp string) string {
	stamp = strings.TrimSpace(stamp)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02"} {
		if t, err := time.Parse(layout, stamp); err == nil {
			return t.UTC().Format("2006-01-02")
		}
	}
	return ""
}

// npmDeprecated reads the "deprecated" field, which is a message string. Some old
// packages use a bare true, which still means deprecated.
func npmDeprecated(raw json.RawMessage) string {
	var msg string
	if err := json.Unmarshal(raw, &msg); err == nil {
		return clip(msg)
	}
	var flag bool
	if err := json.Unmarshal(raw, &flag); err == nil && flag {
		return "deprecated"
	}
	return ""
}

// npmLicense reads "license", which is an SPDX string, or in older packages an object
// with a "type".
func npmLicense(raw json.RawMessage) string {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return clip(text)
	}
	var obj struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return clip(obj.Type)
	}
	return ""
}

// pypiLicense prefers the SPDX expression, then a short license field, then the trove
// classifier, since the license field is often the whole license text.
func pypiLicense(expression, text string, classifiers []string) string {
	if e := clip(expression); e != "" {
		return e
	}
	if t := clip(text); t != "" && len(t) <= 100 && !strings.ContainsAny(strings.TrimSpace(text), "\n\r") {
		return t
	}
	for _, c := range classifiers {
		if rest, ok := strings.CutPrefix(c, "License :: "); ok {
			parts := strings.Split(rest, " :: ")
			return clip(parts[len(parts)-1])
		}
	}
	return ""
}
