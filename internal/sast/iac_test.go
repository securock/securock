package sast_test

import (
	"slices"
	"strings"
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
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
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
		{"dockerfile insecure downloads and chmod 777", map[string]string{"Dockerfile": "FROM alpine:3.19\nUSER app\nRUN curl -sk https://x.test/a -o /a && chmod -R 777 /a\nRUN wget --no-check-certificate https://x.test/b\nRUN pip install --trusted-host pypi.test pkg\nEXPOSE 8080 22/tcp\n"},
			[]string{"sast:iac/docker-chmod-777", "sast:iac/docker-insecure-download", "sast:iac/docker-ssh-port"}},
		{"dockerfile verified download and safe perms", map[string]string{"Dockerfile": "FROM alpine:3.19\nUSER app\nRUN curl -fsSL --keepalive-time 5 https://x.test/a -o /a && chmod 755 /a\nEXPOSE 8080\n"}, nil},

		{"kubernetes env secret, seccomp, writable fs", map[string]string{"d.yaml": `
apiVersion: apps/v1
kind: Deployment
metadata: {name: d}
spec:
  template:
    spec:
      containers:
        - name: c
          image: registry.test/app:1.0
          env:
            - name: DB_PASSWORD
              value: "Zk3pQ9vLm2XcT7wRb5NhY8aD"
            - name: API_TOKEN
              valueFrom: {secretKeyRef: {name: s, key: t}}
            - name: LOG_LEVEL
              value: debug
          securityContext:
            readOnlyRootFilesystem: false
            seccompProfile: {type: Unconfined}
`}, []string{"sast:iac/hardcoded-secret", "sast:iac/seccomp-unconfined", "sast:iac/writable-root-filesystem"}},
		{"kubernetes rbac wildcard and cluster-admin for default account", map[string]string{"r.yaml": `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: all}
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: b}
roleRef: {kind: ClusterRole, name: cluster-admin, apiGroup: rbac.authorization.k8s.io}
subjects:
  - {kind: ServiceAccount, name: default, namespace: app}
  - {kind: User, name: alice}
`}, []string{"sast:iac/cluster-admin-binding", "sast:iac/rbac-wildcard"}},
		{"cluster-admin for a named user is fine", map[string]string{"r.yaml": `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: b}
roleRef: {kind: ClusterRole, name: cluster-admin}
subjects:
  - {kind: User, name: alice}
`}, nil},
		{"compose env secret, security_opt and root user", map[string]string{"docker-compose.yml": `
services:
  web:
    image: app:1.0
    user: root
    security_opt:
      - seccomp:unconfined
    environment:
      DB_PASSWORD: Zk3pQ9vLm2XcT7wRb5NhY8aD
      MODE: prod
  worker:
    image: app:1.0
    environment:
      - API_SECRET=${API_SECRET}
`}, []string{"sast:iac/hardcoded-secret", "sast:iac/run-as-root", "sast:iac/seccomp-unconfined"}},

		{"actions write-all, unsecure commands, unpinned action", map[string]string{".github/workflows/ci.yml": `
on: push
permissions: write-all
env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: true
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./local-action
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
`}, []string{"sast:iac/actions-unpinned", "sast:iac/actions-unsecure-commands", "sast:iac/actions-write-all"}},
		{"actions reusable workflow pinned by tag", map[string]string{".github/workflows/ci.yml": `
on: push
jobs:
  j:
    uses: acme/shared/.github/workflows/build.yml@main
`}, []string{"sast:iac/actions-unpinned"}},
		{"actions workflow_run head branch injection", map[string]string{".github/workflows/wr.yml": `
on:
  workflow_run: {workflows: [ci], types: [completed]}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.workflow_run.head_branch }}"
`}, []string{"sast:iac/actions-script-injection"}},

		{"terraform public access block, imdsv1, cloudfront", map[string]string{"main.tf": `
resource "aws_s3_bucket_public_access_block" "b" {
  bucket              = "x"
  block_public_acls   = false
  block_public_policy = true
}
resource "aws_instance" "i" {
  ami = "ami-123"
  metadata_options {
    http_tokens = "optional"
  }
}
resource "aws_cloudfront_distribution" "c" {
  default_cache_behavior {
    viewer_protocol_policy = "allow-all"
  }
}
`}, []string{"sast:iac/imds-v1", "sast:iac/insecure-transport", "sast:iac/public-bucket"}},
		{"terraform imdsv2 and blocked public access are fine", map[string]string{"main.tf": `
resource "aws_s3_bucket_public_access_block" "b" {
  block_public_acls = true
}
resource "aws_instance" "i" {
  metadata_options {
    http_tokens = "required"
  }
}
`}, nil},
		{"terraform gcp public iam and open firewall", map[string]string{"main.tf": `
resource "google_storage_bucket_iam_member" "m" {
  bucket = "b"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
resource "google_compute_firewall" "f" {
  name          = "ssh"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
`}, []string{"sast:iac/open-ingress", "sast:iac/public-iam"}},
		{"terraform gcp firewall on https is fine", map[string]string{"main.tf": `
resource "google_compute_firewall" "f" {
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}
`}, nil},
		{"terraform azure open rdp, plain http storage", map[string]string{"main.tf": `
resource "azurerm_network_security_rule" "r" {
  direction              = "Inbound"
  access                 = "Allow"
  source_address_prefix  = "*"
  destination_port_range = "3389"
}
resource "azurerm_network_security_group" "g" {
  security_rule {
    name                   = "web"
    direction              = "Inbound"
    access                 = "Allow"
    source_address_prefix  = "*"
    destination_port_range = "443"
  }
}
resource "azurerm_storage_account" "s" {
  enable_https_traffic_only       = false
  allow_nested_items_to_be_public = true
}
`}, []string{"sast:iac/insecure-transport", "sast:iac/open-ingress", "sast:iac/public-bucket"}},
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

func TestDockerInsecureDownloadFlagsEachLine(t *testing.T) {
	got := analyze(t, map[string]string{"Dockerfile": "FROM alpine:3.19\nUSER app\nRUN curl -sk https://x.test/a\nRUN wget --no-check-certificate https://x.test/b\nRUN pip install --trusted-host pypi.test pkg\nRUN git config --global http.sslVerify false\nRUN npm config set strict-ssl false\n"})
	if n := strings.Count(strings.Join(got, ","), "sast:iac/docker-insecure-download"); n != 5 {
		t.Fatalf("got %d insecure-download findings in %v, want 5", n, got)
	}
}
