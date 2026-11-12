package control

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
)

const consoleScript = `let token='';const el=id=>document.getElementById(id);async function api(path,method='GET',body){const r=await fetch('/api/v1/'+path,{method,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});if(!r.ok)throw Error('Request rejected ('+r.status+')');return (await r.json()).data}async function load(){try{const me=await api('me');el('who').textContent=me.tenant+' / '+me.subject+' / '+me.roles.join(', ');const p=await api('projects');el('project').replaceChildren();for(const x of p){const o=document.createElement('option');o.value=x.id;o.textContent=x.name+' ('+x.owner+')';el('project').append(o)}const jobs=await api('jobs');el('jobs').replaceChildren();for(const j of jobs){const tr=document.createElement('tr');for(const v of [j.id,j.project,j.status,j.created]){const td=document.createElement('td');td.textContent=v;tr.append(td)}const td=document.createElement('td');const b=document.createElement('button');b.textContent='View results';b.onclick=async()=>{try{el('details').textContent=JSON.stringify(await api('jobs/'+encodeURIComponent(j.id)),null,2)}catch(e){el('error').textContent=e.message}};td.append(b);tr.append(td);el('jobs').append(tr)}el('error').textContent=''}catch(e){el('error').textContent=e.message}}el('login').onclick=()=>{token=el('token').value;el('token').value='';load()};el('logout').onclick=()=>{token='';el('jobs').replaceChildren();el('details').textContent='';el('who').textContent='Signed out'};el('refresh').onclick=load;el('create').onclick=async()=>{try{await api('projects','POST',{id:el('projectid').value,name:el('name').value,owner:el('owner').value});await load()}catch(e){el('error').textContent=e.message}};el('scan').onclick=async()=>{try{await api('jobs','POST',{id:crypto.randomUUID(),project:el('project').value});await load()}catch(e){el('error').textContent=e.message}};`

func console(w http.ResponseWriter) {
	sum := sha256.Sum256([]byte(consoleScript))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	_, _ = io.WriteString(w, `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Securock team console</title><h1>Securock team console</h1><p>Use your organization's OIDC API access token. It stays in page memory.</p><label>Access token <input id="token" type="password" autocomplete="off"></label><button id="login">Sign in</button><button id="logout">Sign out</button><p id="who"></p><p id="error" role="alert"></p><h2>Register project</h2><label>Project ID <input id="projectid"></label><label>Name <input id="name"></label><label>Owner <input id="owner"></label><button id="create">Register</button><h2>Scans</h2><label>Project <select id="project"></select></label><button id="scan">Request scan</button><button id="refresh">Refresh</button><table><thead><tr><th>Job</th><th>Project</th><th>Status</th><th>Created</th><th>Results</th></tr></thead><tbody id="jobs"></tbody></table><pre id="details"></pre><script>`+consoleScript+`</script></html>`)
}
