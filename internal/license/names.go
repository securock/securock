package license

import "strings"

var known = map[string]string{}

func init() {
	for _, id := range strings.Fields(`
0BSD AFL-3.0 AGPL-1.0-only AGPL-1.0-or-later AGPL-3.0-only AGPL-3.0-or-later Apache-1.1 Apache-2.0
Artistic-1.0 Artistic-2.0 BlueOak-1.0.0 BSD-1-Clause BSD-2-Clause BSD-2-Clause-Patent BSD-3-Clause
BSD-3-Clause-Clear BSD-4-Clause BSL-1.0 BUSL-1.1 Beerware CC-BY-3.0 CC-BY-4.0 CC-BY-NC-4.0
CC-BY-NC-SA-4.0 CC-BY-ND-4.0 CC-BY-SA-3.0 CC-BY-SA-4.0 CC0-1.0 CDDL-1.0 CDDL-1.1 CPAL-1.0 ECL-2.0
EPL-1.0 EPL-2.0 EUPL-1.1 EUPL-1.2 FTL GPL-1.0-only GPL-1.0-or-later GPL-2.0-only GPL-2.0-or-later
GPL-3.0-only GPL-3.0-or-later HPND ISC JSON LGPL-2.0-only LGPL-2.0-or-later LGPL-2.1-only
LGPL-2.1-or-later LGPL-3.0-only LGPL-3.0-or-later Libpng LPPL-1.3c MIT MIT-0 MPL-1.1 MPL-2.0 MS-PL
MS-RL MulanPSL-2.0 NCSA OFL-1.1 OpenSSL OSL-3.0 PostgreSQL PSF-2.0 Python-2.0 Ruby SSPL-1.0
Unicode-DFS-2016 Unlicense UPL-1.0 Vim W3C WTFPL X11 Zlib ZPL-2.1 bzip2-1.0.6 curl`) {
		known[strings.ToLower(id)] = id
	}
}

// deprecated maps SPDX identifiers that predate the -only / -or-later split to their
// current meaning. A bare "GPL-3.0" has always meant version 3 only.
var deprecated = map[string]string{
	"agpl-3.0":  "AGPL-3.0-only",
	"agpl-3.0+": "AGPL-3.0-or-later",
	"gpl-2.0":   "GPL-2.0-only",
	"gpl-2.0+":  "GPL-2.0-or-later",
	"gpl-3.0":   "GPL-3.0-only",
	"gpl-3.0+":  "GPL-3.0-or-later",
	"lgpl-2.0":  "LGPL-2.0-only",
	"lgpl-2.0+": "LGPL-2.0-or-later",
	"lgpl-2.1":  "LGPL-2.1-only",
	"lgpl-2.1+": "LGPL-2.1-or-later",
	"lgpl-3.0":  "LGPL-3.0-only",
	"lgpl-3.0+": "LGPL-3.0-or-later",
	"gpl-1.0":   "GPL-1.0-only",
	"gpl-1.0+":  "GPL-1.0-or-later",
}

// aliases maps license names that registries use, such as PyPI trove classifiers, to SPDX.
// Names that do not pick out one license, like "BSD License", are left out on purpose.
var aliases = map[string]string{
	"mit license":                                             "MIT",
	"the mit license":                                         "MIT",
	"apache software license":                                 "Apache-2.0",
	"apache license 2.0":                                      "Apache-2.0",
	"apache 2.0":                                              "Apache-2.0",
	"isc license (iscl)":                                      "ISC",
	"isc license":                                             "ISC",
	"mozilla public license 2.0 (mpl 2.0)":                    "MPL-2.0",
	"the unlicense (unlicense)":                               "Unlicense",
	"python software foundation license":                      "PSF-2.0",
	"gnu general public license v2 (gplv2)":                   "GPL-2.0-only",
	"gnu general public license v2 or later (gplv2+)":         "GPL-2.0-or-later",
	"gnu general public license v3 (gplv3)":                   "GPL-3.0-only",
	"gnu general public license v3 or later (gplv3+)":         "GPL-3.0-or-later",
	"gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.0-or-later",
	"gnu lesser general public license v3 (lgplv3)":           "LGPL-3.0-only",
	"gnu lesser general public license v3 or later (lgplv3+)": "LGPL-3.0-or-later",
	"gnu affero general public license v3":                    "AGPL-3.0-only",
	"gnu affero general public license v3 or later (agplv3+)": "AGPL-3.0-or-later",
}

// Normalize returns the canonical SPDX spelling of a license identifier or registry name:
// case is corrected, the deprecated GPL spellings are resolved, and known registry names
// are mapped. Anything unrecognized comes back trimmed and otherwise unchanged.
func Normalize(name string) string {
	name = strings.TrimSpace(name)
	key := strings.ToLower(name)
	if id, ok := aliases[key]; ok {
		return id
	}
	if id, ok := deprecated[key]; ok {
		return id
	}
	if id, ok := known[key]; ok {
		return id
	}
	return name
}

// Known reports whether id is a recognized SPDX identifier.
func Known(id string) bool {
	_, ok := known[strings.ToLower(id)]
	return ok
}

// NormalizeExpression normalizes every license in an expression and rewrites it with
// upper-case operators. Text that is not an expression is normalized as one name.
func NormalizeExpression(declared string) string {
	if n, ok := parse(declared); ok {
		return n.String()
	}
	return Normalize(declared)
}

// IsSPDX reports whether declared is an expression made only of recognized SPDX
// identifiers, which is what SBOM formats require of a license expression.
func IsSPDX(declared string) bool {
	n, ok := parse(declared)
	if !ok {
		return false
	}
	for _, id := range n.ids() {
		if !Known(id) {
			return false
		}
	}
	return true
}
