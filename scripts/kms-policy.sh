#!/usr/bin/env bash
# Renders the KMS key policy for one enclave build, or prints PCR3.
#
#   kms-policy.sh pcr3 <parent-role-arn>        PCR3 for that role
#   kms-policy.sh render <build-enclave.json> <out.json>
#   kms-policy.sh self-test                     PCR3 of AWS's documented example
#
# render reads PCR0/1/2 from nitro-cli's build-enclave output and computes
# PCR3 from PARENT_ROLE_ARN (default: the placeholder account's
# signer-parent role). PCR3 is SHA-384 over 48 zero bytes followed by the
# role ARN, per the AWS Nitro Enclaves user guide ("Where to get an
# enclave's measurements"). It pins the IAM role of the parent instance;
# PCR4 (instance ID) is left out so a node can move to a new instance.
#
# Environment for render: ACCOUNT_ID (111122223333), ADMIN_ROLE
# (signer-kms-admin), PARENT_INSTANCE_ROLE (signer-parent), PARENT_ROLE_ARN.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

pcr3() {
  python3 -I -c 'import hashlib,sys; h=hashlib.sha384(); h.update(b"\0"*48); h.update(sys.argv[1].encode()); print(h.hexdigest())' "$1"
}

case "${1:-}" in
  pcr3)
    [ $# -eq 2 ] || { echo "usage: $0 pcr3 <role-arn>" >&2; exit 2; }
    pcr3 "$2"
    ;;
  self-test)
    # Example and output from the AWS Nitro Enclaves user guide,
    # set-up-attestation.html#pcr3.
    want=78fce75db17cd4e0a3fb8dad3ad128ca5e77edbb2b2c7f75329dccd99aa5f6ef4fc1f1a452e315b9e98f9e312e6921e6
    got="$(pcr3 arn:aws:iam::123456789012:role/Webserver)"
    if [ "$got" = "$want" ]; then log "PCR3 self-test: matches the AWS example"; else log "PCR3 self-test FAILED: $got"; exit 1; fi
    ;;
  render)
    [ $# -eq 3 ] || { echo "usage: $0 render <build-enclave.json> <out.json>" >&2; exit 2; }
    in="$2" out="$3"
    pcr() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["Measurements"][sys.argv[2]])' "$in" "$1"; }
    export ACCOUNT_ID="${ACCOUNT_ID:-111122223333}"
    export ADMIN_ROLE="${ADMIN_ROLE:-signer-kms-admin}"
    export PARENT_INSTANCE_ROLE="${PARENT_INSTANCE_ROLE:-signer-parent}"
    role_arn="${PARENT_ROLE_ARN:-arn:aws:iam::$ACCOUNT_ID:role/$PARENT_INSTANCE_ROLE}"
    # shellcheck disable=SC2016 # envsubst takes the variable names, not their values
    PCR0="$(pcr PCR0)" PCR1="$(pcr PCR1)" PCR2="$(pcr PCR2)" PCR3="$(pcr3 "$role_arn")" \
      envsubst '${ACCOUNT_ID} ${ADMIN_ROLE} ${PARENT_INSTANCE_ROLE} ${PCR0} ${PCR1} ${PCR2} ${PCR3}' \
      <"$ROOT/platform-aws/deploy/kms-key-policy.json.tmpl" >"$out"
    python3 -I -m json.tool "$out" >/dev/null
    # shellcheck disable=SC2016 # a literal "${" left in the output
    if grep -q '\${' "$out"; then echo "$out: unrendered variable" >&2; exit 1; fi
    log "KMS policy for $role_arn: $out (PCR3 $(pcr3 "$role_arn" | cut -c1-16)...)"
    ;;
  *)
    echo "usage: $0 pcr3 <role-arn> | render <build-enclave.json> <out.json> | self-test" >&2
    exit 2
    ;;
esac
