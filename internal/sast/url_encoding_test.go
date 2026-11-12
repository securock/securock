package sast_test

import (
	"slices"
	"strings"
	"testing"
)

func TestURLEncodingIsNotValidation(t *testing.T) {
	for _, tt := range []struct {
		language, file, source string
		encoders               []string
	}{
		{"go", "app.go", `package main
import ("net/http"; "net/url"; "os")
func handle(w http.ResponseWriter, r *http.Request) {
 value := ENCODE(r.FormValue("value"))
 http.Get("https://" + value + "/data")
 http.Redirect(w, r, "https://" + value + "/login", 302)
 os.ReadFile("/srv/files/" + value + "/secret.txt")
}`, []string{"url.QueryEscape", "url.PathEscape"}},
		{"py", "app.py", `from flask import request, redirect
import urllib.parse
import requests
def handle():
    value = ENCODE(request.args['value'])
    requests.get('https://' + value + '/data')
    redirect('https://' + value + '/login')
    open('/srv/files/' + value + '/secret.txt')
`, []string{"urllib.parse.quote", "urllib.parse.quote_plus"}},
		{"php", "app.php", `<?php
$value = ENCODE($_GET['value']);
curl_init('https://' . $value . '/data');
header('Location: https://' . $value . '/login');
fopen('/srv/files/' . $value . '/secret.txt', 'r');
`, []string{"urlencode", "rawurlencode"}},
		{"rb", "app.rb", `require 'cgi'
require 'uri'
require 'net/http'
def handle
  value = ENCODE(params[:value])
  Net::HTTP.get('https://' + value + '/data')
  redirect_to('https://' + value + '/login')
  File.read('/srv/files/' + value + '/secret.txt')
end
`, []string{"CGI.escape", "URI.encode_www_form_component"}},
		{"java", "App.java", `import javax.servlet.http.*;
import java.net.*;
import java.io.*;
public class App {
 void handle(HttpServletRequest req, HttpServletResponse resp) throws Exception {
  String value = ENCODE(req.getParameter("value"));
  URL u = new URL("https://" + value + "/data");
  u.openConnection();
  resp.sendRedirect("https://" + value + "/login");
  new FileInputStream("/srv/files/" + value + "/secret.txt");
 }
}`, []string{"java.net.URLEncoder.encode", "org.owasp.encoder.Encode.forUriComponent"}},
		{"cs", "App.cs", `using System;
using System.IO;
using System.Net;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;
[ApiController]
public class App : ControllerBase {
 private readonly HttpClient _http;
 [HttpGet]
 public IActionResult Handle([FromQuery] string input) {
  var value = ENCODE(input);
  _http.GetStringAsync("https://" + value + "/data");
  File.ReadAllText("/srv/files/" + value + "/secret.txt");
  return Redirect("https://" + value + "/login");
 }
}`, []string{"WebUtility.UrlEncode", "Uri.EscapeDataString"}},
	} {
		for _, encoder := range tt.encoders {
			t.Run(tt.language+"/"+encoder, func(t *testing.T) {
				want := []string{"sast:" + tt.language + "/open-redirect", "sast:" + tt.language + "/path-traversal", "sast:" + tt.language + "/ssrf"}
				source := strings.ReplaceAll(tt.source, "ENCODE", encoder)
				if got := slices.Compact(analyze(t, map[string]string{tt.file: source})); !slices.Equal(got, want) {
					t.Fatalf("got %v, want %v", got, want)
				}
			})
		}
	}
}

func TestGoEncodedURLContexts(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		want       []string
	}{
		{"fixed host path", `http.Get("https://api.example.com/items/" + url.PathEscape(value))`, nil},
		{"fixed host query", `http.Get("https://api.example.com?q=" + url.QueryEscape(value))`, nil},
		{"local redirect query", `http.Redirect(w, r, "/login?next=" + url.QueryEscape(value), 302)`, nil},
		{"host suffix", `http.Get("https://api.example.com" + url.PathEscape(value))`, []string{"sast:go/ssrf"}},
		{"network relative redirect", `http.Redirect(w, r, "//" + url.QueryEscape(value), 302)`, []string{"sast:go/open-redirect"}},
		{"unescaped suffix", `http.Get("https://api.example.com/items/" + value)`, []string{"sast:go/ssrf"}},
		{"prefix removed", `target := "https://api.example.com/items/" + url.PathEscape(value)
http.Get("https://" + strings.TrimPrefix(target, "https://api.example.com/items/"))`, []string{"sast:go/ssrf"}},
		{"filesystem path", `os.ReadFile("/srv/files/" + url.PathEscape(value))`, []string{"sast:go/path-traversal"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := `package main
import ("net/http"; "net/url"; "os"; "strings")
func handle(w http.ResponseWriter, r *http.Request) {
value := r.FormValue("value")
` + tt.body + "\n}"
			if got := slices.Compact(analyze(t, map[string]string{"app.go": source})); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
