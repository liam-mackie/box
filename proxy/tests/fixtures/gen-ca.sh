#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout "$here/ca.key" -out "$here/ca.crt" \
  -days 3650 -sha256 \
  -subj "/CN=box MITM CA/O=box" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
chmod 600 "$here/ca.key"
echo "wrote $here/ca.crt and $here/ca.key (gitignored)"
