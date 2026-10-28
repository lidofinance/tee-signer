#!/usr/bin/env bash
# Makes a local test CA and one client certificate for the Dirk fork, all
# ECDSA P-256, in a private directory outside the repo (mode 700, key files
# 600). Only client-ca.pem (public) goes into the image build context.
#
#   make-test-ca.sh DIR       DIR: a private directory outside the repo
#
# Files:
#   client-ca.pem       CA certificate, goes into the runner image (public)
#   client-ca-key.pem   CA private key, never leaves DIR
#   client.pem          client certificate for the Dirk fork (public)
#   client-key.pem      its private key
#
# Refuses to overwrite an existing CA. Never prints key material and never
# passes it on a command line: openssl reads and writes key files by path.
set -euo pipefail

DIR="${1:?usage: make-test-ca.sh DIR (a private directory outside the repo)}"
CA_DAYS="${CA_DAYS:-3650}"
CLIENT_DAYS="${CLIENT_DAYS:-825}"

umask 077
mkdir -p "$DIR"
chmod 700 "$DIR"
if [ -e "$DIR/client-ca-key.pem" ] || [ -e "$DIR/client-ca.pem" ]; then
  echo "make-test-ca: $DIR already has a CA, not overwriting it" >&2
  exit 1
fi

ec_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

ec_key "$DIR/client-ca-key.pem"
openssl req -x509 -new -sha256 -days "$CA_DAYS" \
  -key "$DIR/client-ca-key.pem" \
  -subj "/CN=signer-poc azure test client CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$DIR/client-ca.pem"

ec_key "$DIR/client-key.pem"
csr="$(mktemp "$DIR/client.csr.XXXXXX")"
ext="$(mktemp "$DIR/client.ext.XXXXXX")"
trap 'rm -f "$csr" "$ext"' EXIT
openssl req -new -sha256 -key "$DIR/client-key.pem" -subj "/CN=dirk-fork-test-client" -out "$csr"
printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" \
  "extendedKeyUsage=clientAuth" >"$ext"
openssl x509 -req -sha256 -days "$CLIENT_DAYS" -in "$csr" \
  -CA "$DIR/client-ca.pem" -CAkey "$DIR/client-ca-key.pem" -CAcreateserial \
  -extfile "$ext" -out "$DIR/client.pem"

chmod 600 "$DIR"/*-key.pem "$DIR"/client-ca.srl
chmod 644 "$DIR/client-ca.pem" "$DIR/client.pem"
openssl verify -purpose sslclient -CAfile "$DIR/client-ca.pem" "$DIR/client.pem" >&2
echo "make-test-ca: wrote $DIR (CA sha256 $(openssl x509 -in "$DIR/client-ca.pem" -noout -fingerprint -sha256 | cut -d= -f2))" >&2
