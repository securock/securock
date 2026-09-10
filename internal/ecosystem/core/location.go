package core

import (
	"net/url"
	"strings"
)

func RemoteLocation(raw string) string {
	u := parseRemote(raw)
	if u == nil {
		return ""
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	u.RawFragment = ""
	return strings.TrimRight(u.String(), "/")
}

func RemoteRevision(raw string) string {
	u := parseRemote(raw)
	if u == nil {
		return ""
	}
	return u.Fragment
}

func parseRemote(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	if strings.EqualFold(u.Scheme, "file") {
		return nil
	}
	return u
}
