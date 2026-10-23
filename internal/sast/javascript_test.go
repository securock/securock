package sast_test

import (
	"slices"
	"testing"
)

func TestJavaScript(t *testing.T) {
	tests := []struct {
		name string
		file string
		src  string
		want []string
	}{
		{"express sql concat", "app.js", `
const express = require('express');
const app = express();
app.get('/u', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id);
});`, []string{"sast:js/sql-injection"}},
		{"template string", "app.js", `
app.get('/u', async (req, res) => {
  const id = req.params.id;
  await pool.query(` + "`SELECT * FROM t WHERE id = ${id}`" + `);
});`, []string{"sast:js/sql-injection"}},
		{"parameterized query is safe", "app.js", `
app.get('/u', (req, res) => {
  db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
});`, nil},
		{"command injection exec", "app.js", `
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));
});`, []string{"sast:js/command-injection"}},
		{"import syntax and alias", "app.ts", `
import { exec as run } from 'node:child_process';
export function h(req: Request) {
  run('ls ' + req.body.dir);
}`, []string{"sast:js/command-injection"}},
		{"path traversal", "app.js", `
const fs = require('fs');
app.get('/f', (req, res) => {
  res.send(fs.readFileSync('/srv/' + req.query.name));
});`, []string{"sast:js/path-traversal"}},
		{"basename sanitizes path", "app.js", `
const fs = require('fs');
const path = require('path');
app.get('/f', (req, res) => {
  const data = fs.readFileSync('/srv/' + path.basename(req.query.name));
});`, nil},
		{"xss via res.send", "app.js", `
app.get('/h', (req, res) => {
  res.send('<h1>' + req.query.name + '</h1>');
});`, []string{"sast:js/xss"}},
		{"escape-html sanitizes", "app.js", `
const escapeHtml = require('escape-html');
app.get('/h', (req, res) => {
  res.send('<h1>' + escapeHtml(req.query.name) + '</h1>');
});`, nil},
		{"innerHTML assignment", "ui.js", `
const q = new URLSearchParams(location.search).get('q');
document.getElementById('o').innerHTML = q;`, []string{"sast:js/xss"}},
		{"ssrf via axios", "app.js", `
const axios = require('axios');
app.get('/p', async (req, res) => {
  const r = await axios.get(req.query.url);
  res.json(r.data);
});`, []string{"sast:js/ssrf"}},
		{"open redirect", "app.js", `
app.get('/go', (req, res) => { res.redirect(req.query.next); });`, []string{"sast:js/open-redirect"}},
		{"eval", "app.js", `
app.post('/c', (req, res) => { eval(req.body.code); });`, []string{"sast:js/code-injection"}},
		{"parseInt sanitizes", "app.js", `
app.get('/u', (req, res) => {
  const id = parseInt(req.query.id, 10);
  db.query("SELECT * FROM users WHERE id = " + id);
});`, nil},
		{"destructuring", "app.js", `
app.get('/u', (req, res) => {
  const { id } = req.query;
  db.query("SELECT " + id);
});`, []string{"sast:js/sql-injection"}},
		{"allowlist guard", "app.js", `
const COLS = ['name', 'age'];
app.get('/u', (req, res) => {
  const col = req.query.sort;
  if (!COLS.includes(col)) { return res.status(400).end(); }
  db.query("SELECT * FROM t ORDER BY " + col);
});`, nil},
		{"through a helper function", "app.js", `
function find(name) { return db.query("SELECT * FROM u WHERE n = '" + name + "'"); }
app.get('/u', (req, res) => { find(req.query.n); });`, []string{"sast:js/sql-injection"}},
		{"across files", "routes.js", `
const { find } = require('./repo');
app.get('/u', (req, res) => { find(req.query.n); });`, []string{"sast:js/sql-injection"}},
		{"class method", "svc.ts", `
class Repo {
  find(name: string) { return db.query("SELECT '" + name + "'"); }
}
class Ctl {
  repo = new Repo();
  get(req: any) { return this.repo.find(req.query.n); }
}`, []string{"sast:js/sql-injection"}},
		{"unrelated socket send is not xss", "app.js", `
app.get('/h', (req, res) => { socket.send(req.query.m); });`, nil},
		{"local variable named params is not a source", "app.js", `
function f() { const params = {a: 'x'}; db.query("SELECT " + params.a); }`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{tt.file: tt.src}
			if tt.name == "across files" {
				files["repo.js"] = `exports.find = function (name) { return db.query("SELECT * FROM u WHERE n = '" + name + "'"); };
module.exports.find = exports.find;`
				files["repo.js"] = `function find(name) { return db.query("SELECT * FROM u WHERE n = '" + name + "'"); }
module.exports = { find };`
			}
			got := analyze(t, files)
			got = slices.Compact(got)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJSX(t *testing.T) {
	tests := []struct {
		name string
		file string
		src  string
		want []string
	}{
		{"dangerouslySetInnerHTML from the URL", "A.jsx", `
export function A() {
  const q = new URLSearchParams(window.location.search).get("q");
  return <div dangerouslySetInnerHTML={{ __html: q }} />;
}`, []string{"sast:js/xss"}},
		{"sanitized with DOMPurify", "C.jsx", `
import DOMPurify from "dompurify";
export function C() {
  const q = window.location.hash;
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(q) }} />;
}`, nil},
		{"constant html is safe", "D.jsx", `
export function D() { return <div dangerouslySetInnerHTML={{ __html: "<b>hi</b>" }} />; }`, nil},
		{"plain text child is escaped by React", "E.jsx", `
export function E() { const q = window.location.hash; return <p>{q}</p>; }`, nil},
		{"Next.js server props", "page.jsx", `
export async function getServerSideProps(context) {
  const html = context.query.html;
  return { props: { html } };
}
export default function P({ html }) { return <div dangerouslySetInnerHTML={{ __html: window.location.search }} />; }`, []string{"sast:js/xss"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slices.Compact(analyze(t, map[string]string{tt.file: tt.src}))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
