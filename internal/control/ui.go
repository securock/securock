package control

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"io"
	"net/http"
)

//go:embed console.js
var consoleScript string

//go:embed console.css
var consoleStyle string

func console(w http.ResponseWriter, sso bool) {
	scriptHash := sha256.Sum256([]byte(consoleScript))
	styleHash := sha256.Sum256([]byte(consoleStyle))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'sha256-"+base64.StdEncoding.EncodeToString(scriptHash[:])+"'; style-src 'sha256-"+base64.StdEncoding.EncodeToString(styleHash[:])+"'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	loginLink := ""
	if sso {
		loginLink = `<p><a href="/auth/login">Sign in with your organization</a></p>`
	}
	_, _ = io.WriteString(w, `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Securock team console</title><style>`+consoleStyle+`</style><header><div><h1>Securock</h1><p>Security work, from detection to resolution</p>`+loginLink+`</div><div><p id="who">Sign in to your workspace</p><button id="logout">Sign out</button></div></header><main><details><summary>Use an API token</summary><div class="fields"><label>Access token<input id="token" type="password" autocomplete="off"></label><button id="login">Sign in</button></div><p class="hint">The token stays in page memory and is cleared on sign-out.</p></details><p id="error" role="alert"></p><nav aria-label="Workspace"><a href="#scans">Scans</a><a href="#work">Work queue</a><a href="#exceptions">Exceptions</a><button id="refresh">Refresh</button><button id="export-audit">Export audit</button></nav><div class="metrics"><article><span>Projects</span><strong id="project-count">0</strong></article><article><span>Open findings</span><strong id="open-count">0</strong></article><article><span>Queued or running</span><strong id="queue-count">0</strong></article></div><section id="scans"><h2>Projects and scans</h2><details id="project-form" hidden><summary>Register a project</summary><div class="fields"><label>Project ID<input id="projectid"></label><label>Project name<input id="name"></label><label>Project owner<input id="owner"></label><button id="create">Register</button></div></details><div class="row"><label>Project<select id="project"></select></label><button id="scan" disabled>Request scan</button></div><div class="table-wrap"><table><thead><tr><th>Project</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead><tbody id="jobs"></tbody></table></div><details id="report"><summary>Execution details</summary><pre id="details"></pre></details></section><section id="work"><h2>Shared work queue</h2><p class="hint">Resolution follows comparable scan evidence. Missing coverage remains visible.</p><div class="table-wrap"><table><thead><tr><th>Project</th><th>State</th><th>Severity</th><th>Finding</th><th>Owner and due date</th></tr></thead><tbody id="issues"></tbody></table></div></section><section id="exceptions"><h2>Exception review</h2><p class="hint">Exceptions require a different reviewer, an exact artifact and rule, and an expiry within 30 days.</p><details id="approval-form" hidden><summary>Request an exception</summary><div class="fields"><label>Artifact SHA-256<input id="artifact" maxlength="64"></label><label>Rule ID<input id="rule"></label><label>Expires (UTC)<input id="expires" type="datetime-local"></label><label>Reason<textarea id="reason"></textarea></label><button id="request-approval">Request review</button></div></details><div class="table-wrap"><table><thead><tr><th>Rule</th><th>Artifact</th><th>Requester</th><th>Status</th><th>Expires</th><th>Review</th></tr></thead><tbody id="approvals"></tbody></table></div></section></main><footer>Protect exported findings and audit records as workspace security data.</footer><script>`+consoleScript+`</script></html>`)
}
