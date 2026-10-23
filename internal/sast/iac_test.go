package sast_test

import (
	"slices"
	"testing"
)

func TestIaC(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"dockerfile as root with latest", map[string]string{"Dockerfile": "FROM node:latest\nRUN npm ci\nCMD [\"node\", \"app.js\"]\n"},
			[]string{"sast:iac/docker-root-user", "sast:iac/docker-unpinned-image"}},
		{"hardened dockerfile", map[string]string{"Dockerfile": "FROM node:20.11-alpine\nRUN npm ci\nUSER node\nCMD [\"node\", \"app.js\"]\n"}, nil},
		{"digest pinned base is fine", map[string]string{"Dockerfile": "FROM gcr.io/distroless/static@sha256:" + "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90" + "\nUSER 65532\n"}, nil},
		{"multi-stage: only the final stage matters for USER", map[string]string{"Dockerfile": "FROM golang:1.22 AS build\nRUN go build -o /app\nFROM gcr.io/distroless/static:nonroot\nCOPY --from=build /app /app\nUSER 65532:65532\n"}, nil},
		{"stage alias is not an unpinned image", map[string]string{"Dockerfile": "FROM golang:1.22 AS build\nFROM build AS test\nUSER nobody\n"}, nil},
		{"curl pipe to shell and remote ADD", map[string]string{"Dockerfile": "FROM alpine:3.19\nUSER app\nADD https://example.com/x.tar.gz /x\nRUN curl -fsSL https://example.com/i.sh | sh\n"},
			[]string{"sast:iac/docker-add-remote", "sast:iac/docker-pipe-to-shell"}},
		{"secret in ENV", map[string]string{"Dockerfile": "FROM alpine:3.19\nUSER app\nENV API_KEY=Zk3pQ9vLm2XcT7wRb5NhY8aD\nENV API_KEY_FILE=/run/secrets/key\n"}, []string{"sast:iac/hardcoded-secret"}},
		{"continuation lines are joined", map[string]string{"Dockerfile": "FROM alpine:3.19\nUSER app\nRUN apk add curl && \\\n    curl -fsSL https://x.sh | \\\n    bash\n"}, []string{"sast:iac/docker-pipe-to-shell"}},

		{"kubernetes privileged pod", map[string]string{"pod.yaml": `
apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  hostNetwork: true
  containers:
    - name: c
      image: nginx:1.25
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        runAsUser: 0
        capabilities:
          add: ["SYS_ADMIN"]
  volumes:
    - name: h
      hostPath: {path: /var/run/docker.sock}
`}, []string{"sast:iac/dangerous-capability", "sast:iac/docker-socket-mount", "sast:iac/host-namespace", "sast:iac/host-path-mount", "sast:iac/privilege-escalation", "sast:iac/privileged-container", "sast:iac/run-as-root"}},
		{"hardened deployment", map[string]string{"d.yaml": `
apiVersion: apps/v1
kind: Deployment
metadata: {name: d}
spec:
  template:
    spec:
      containers:
        - name: c
          image: registry.example.com/app:1.4.2
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            privileged: false
            capabilities: {drop: ["ALL"]}
`}, nil},
		{"multi-document file", map[string]string{"m.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: b}\nspec:\n  containers:\n    - name: c\n      image: app:1\n      securityContext: {privileged: true}\n"}, []string{"sast:iac/privileged-container"}},
		{"compose docker socket and host network", map[string]string{"docker-compose.yml": `
services:
  web:
    image: app:1
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`}, []string{"sast:iac/docker-socket-mount", "sast:iac/host-namespace"}},
		{"unrelated yaml is ignored", map[string]string{"config.yaml": "privileged: true\nname: x\n"}, nil},

		{"github actions script injection", map[string]string{".github/workflows/ci.yml": `
name: ci
on: [issues]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
`}, []string{"sast:iac/actions-script-injection"}},
		{"github actions env indirection is safe", map[string]string{".github/workflows/ci.yml": `
on: [issues]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
`}, nil},
		{"pull_request_target checking out the PR head", map[string]string{".github/workflows/pr.yml": `
on: pull_request_target
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`}, []string{"sast:iac/actions-pwn-request"}},
		{"trusted contexts are fine", map[string]string{".github/workflows/ci.yml": `
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.sha }} ${{ github.repository }}"
`}, nil},

		{"terraform open ssh", map[string]string{"main.tf": `
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`}, []string{"sast:iac/open-ingress"}},
		{"terraform https to the world is fine", map[string]string{"main.tf": `
resource "aws_security_group" "web" {
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`}, nil},
		{"terraform public bucket and database", map[string]string{"main.tf": `
resource "aws_s3_bucket" "b" {
  bucket = "x"
  acl    = "public-read"
}
resource "aws_db_instance" "d" {
  publicly_accessible = true
  storage_encrypted   = false
}
`}, []string{"sast:iac/public-bucket", "sast:iac/public-database", "sast:iac/unencrypted-storage"}},
		{"terraform secrets: literal vs variable", map[string]string{"main.tf": `
resource "aws_db_instance" "d" {
  password = "Sup3rS3cretPassw0rd!x"
}
resource "aws_db_instance" "e" {
  password = var.db_password
}
`}, []string{"sast:iac/hardcoded-secret"}},
		{"terraform iam wildcard", map[string]string{"main.tf": `
resource "aws_iam_policy" "p" {
  policy = jsonencode({
    "Statement" = [{ "Effect" = "Allow", "Action" = "*", "Resource" = "*" }]
  })
}
`}, []string{"sast:iac/iam-wildcard"}},
		{"unbalanced terraform is reported, not skipped", map[string]string{"main.tf": "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n"}, []string{"sast:analysis-incomplete"}},
		{"invalid kubernetes yaml is reported", map[string]string{"k.yaml": "apiVersion: v1\nkind: Pod\nspec: [unclosed\n"}, []string{"sast:analysis-incomplete"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slices.Compact(analyze(t, tt.files))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
