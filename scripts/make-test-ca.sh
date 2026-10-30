#!/usr/bin/env bash
# Makes a local test PKI for the client certificates of a runner, one chain
# per client role (signer-protocol/docs/protocol.md, "Client roles"): a root CA; a signing
# intermediate under it with one short-lived signing client certificate and
# one attest-only client certificate (the role of an attestation prover:
# HEALTH, PUBLIC_KEYS, ATTEST and IDENTITY only, a limit on fresh
# attestations); an admin intermediate marked with ADMIN_OID and one admin
# client certificate under it; and a negative case, a client certificate
# marked admin but signed straight by the root, which the runner treats as a
# signing certificate. All ECDSA P-256.
# The private keys stay in DIR (mode 700, key files 600), are never printed
# and never on a command line: openssl reads and writes key files by path.
#
#   scripts/make-test-ca.sh [DIR]        default build/nitro/test-ca
#
# Files:
#   root-ca.pem           root certificate, public. The enclave image pins
#                         this one (CLIENT_CA of scripts/nitro-eif.sh).
#   intermediate.pem      signing intermediate certificate, public,
#                         extended key usage clientAuth. It issues the
#                         signing and attest-only client certificates and
#                         can be replaced without a new image.
#   client.pem            the client certificate followed by the
#                         intermediate: the file a client sends (the
#                         client_cert of attestation-verify/runnerclient)
#   client-key.pem        the client's private key
#   attest-client.pem     the attest-only client certificate followed by the
#                         intermediate: extended key usage clientAuth and
#                         ATTEST_ONLY_OID (backend.AttestOnlyClientOID)
#   attest-client-key.pem its private key
#   admin-ca.pem          admin intermediate certificate, public: extended
#                         key usage clientAuth and ADMIN_OID
#                         (backend.AdminClientOID)
#   admin-client.pem      the admin client certificate (clientAuth and
#                         ADMIN_OID) followed by admin-ca.pem
#   admin-client-key.pem  its private key
#   root-admin-client.pem a client certificate with clientAuth and ADMIN_OID
#                         straight under the root: not admin (negative case)
#   root-admin-client-key.pem its private key
#   root-ca-key.pem, intermediate-key.pem, admin-ca-key.pem
#
# Validity: root 10 years, intermediate 1 year, client certificate 1 day
# (openssl x509 -req counts whole days). A production issuer backdates
# NotBefore by about 5 minutes, which this openssl cannot do.
#
# Refuses to overwrite an existing PKI. Only root-ca.pem goes into an image.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

DIR="${1:-$BUILD/nitro/test-ca}"
# The attest-only role's extended key usage; tee-signer/attls tests that it is
# backend.AttestOnlyClientOID.
ATTEST_ONLY_OID=1.2.840.113556.1.8000.2554.49247.57036.45844.17649.38356.1811430.10320378.1
# The admin role's extended key usage; tee-signer/attls tests that it is
# backend.AdminClientOID.
ADMIN_OID=1.2.840.113556.1.8000.2554.49247.57036.45844.17649.38356.1811430.10320378.2
umask 077
mkdir -p "$DIR"
chmod 700 "$DIR"
if [ -e "$DIR/root-ca.pem" ] || [ -e "$DIR/root-ca-key.pem" ]; then
  echo "make-test-ca: $DIR already has a root CA, not overwriting it" >&2
  exit 1
fi

ec_key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }
tmp="$(mktemp -d "$DIR/tmp.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# sign <csr> <issuer cert> <issuer key> <days> <ext file> <out>
sign() {
  openssl x509 -req -sha256 -in "$1" -CA "$2" -CAkey "$3" -CAcreateserial -days "$4" -extfile "$5" -out "$6" 2>/dev/null
}

ec_key "$DIR/root-ca-key.pem"
openssl req -x509 -new -sha256 -days 3650 -key "$DIR/root-ca-key.pem" \
  -subj "/CN=signer-poc test client root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$DIR/root-ca.pem"

ec_key "$DIR/intermediate-key.pem"
openssl req -new -sha256 -key "$DIR/intermediate-key.pem" -subj "/CN=signer-poc test client intermediate CA" -out "$tmp/inter.csr"
printf '%s\n' "basicConstraints=critical,CA:TRUE,pathlen:0" "keyUsage=critical,keyCertSign,cRLSign" "extendedKeyUsage=clientAuth" >"$tmp/inter.ext"
sign "$tmp/inter.csr" "$DIR/root-ca.pem" "$DIR/root-ca-key.pem" 365 "$tmp/inter.ext" "$DIR/intermediate.pem"

ec_key "$DIR/client-key.pem"
openssl req -new -sha256 -key "$DIR/client-key.pem" -subj "/CN=test-client" -out "$tmp/client.csr"
printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" "extendedKeyUsage=clientAuth" >"$tmp/client.ext"
sign "$tmp/client.csr" "$DIR/intermediate.pem" "$DIR/intermediate-key.pem" 1 "$tmp/client.ext" "$tmp/client.leaf.pem"
cat "$tmp/client.leaf.pem" "$DIR/intermediate.pem" >"$DIR/client.pem"

ec_key "$DIR/attest-client-key.pem"
openssl req -new -sha256 -key "$DIR/attest-client-key.pem" -subj "/CN=attest-prover-test-client" -out "$tmp/attest.csr"
printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" \
  "extendedKeyUsage=clientAuth,$ATTEST_ONLY_OID" >"$tmp/attest.ext"
sign "$tmp/attest.csr" "$DIR/intermediate.pem" "$DIR/intermediate-key.pem" 1 "$tmp/attest.ext" "$tmp/attest.leaf.pem"
cat "$tmp/attest.leaf.pem" "$DIR/intermediate.pem" >"$DIR/attest-client.pem"

# The admin intermediate: the leaf and its direct issuer both carry
# ADMIN_OID, the rule of runner/attls.Role.
ec_key "$DIR/admin-ca-key.pem"
openssl req -new -sha256 -key "$DIR/admin-ca-key.pem" -subj "/CN=signer-poc test admin intermediate CA" -out "$tmp/admin-ca.csr"
printf '%s\n' "basicConstraints=critical,CA:TRUE,pathlen:0" "keyUsage=critical,keyCertSign,cRLSign"   "extendedKeyUsage=clientAuth,$ADMIN_OID" >"$tmp/admin-ca.ext"
sign "$tmp/admin-ca.csr" "$DIR/root-ca.pem" "$DIR/root-ca-key.pem" 365 "$tmp/admin-ca.ext" "$DIR/admin-ca.pem"

printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature"   "extendedKeyUsage=clientAuth,$ADMIN_OID" >"$tmp/admin.ext"
ec_key "$DIR/admin-client-key.pem"
openssl req -new -sha256 -key "$DIR/admin-client-key.pem" -subj "/CN=signer-admin-test-client" -out "$tmp/admin.csr"
sign "$tmp/admin.csr" "$DIR/admin-ca.pem" "$DIR/admin-ca-key.pem" 1 "$tmp/admin.ext" "$tmp/admin.leaf.pem"
cat "$tmp/admin.leaf.pem" "$DIR/admin-ca.pem" >"$DIR/admin-client.pem"

# Negative case: marked admin, issued by the root itself.
ec_key "$DIR/root-admin-client-key.pem"
openssl req -new -sha256 -key "$DIR/root-admin-client-key.pem" -subj "/CN=root-issued-admin-test-client" -out "$tmp/root-admin.csr"
sign "$tmp/root-admin.csr" "$DIR/root-ca.pem" "$DIR/root-ca-key.pem" 1 "$tmp/admin.ext" "$DIR/root-admin-client.pem"

chmod 600 "$DIR"/*-key.pem
chmod 644 "$DIR/root-ca.pem" "$DIR/intermediate.pem" "$DIR/client.pem" "$DIR/attest-client.pem"   "$DIR/admin-ca.pem" "$DIR/admin-client.pem" "$DIR/root-admin-client.pem"
rm -f "$DIR"/*.srl
openssl verify -purpose sslclient -CAfile "$DIR/root-ca.pem" -untrusted "$DIR/intermediate.pem" "$tmp/client.leaf.pem" >&2
openssl verify -purpose sslclient -CAfile "$DIR/root-ca.pem" -untrusted "$DIR/intermediate.pem" "$tmp/attest.leaf.pem" >&2
openssl verify -purpose sslclient -CAfile "$DIR/root-ca.pem" -untrusted "$DIR/admin-ca.pem" "$tmp/admin.leaf.pem" >&2
openssl verify -purpose sslclient -CAfile "$DIR/root-ca.pem" "$DIR/root-admin-client.pem" >&2
log "test PKI in $DIR (root sha256 $(openssl x509 -in "$DIR/root-ca.pem" -noout -fingerprint -sha256 | cut -d= -f2))"
