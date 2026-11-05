#!/usr/bin/env bash
# The hashicorp/aws provider in a folder for TF_PLUGIN_DIR of
# scripts/tf-validate.sh and scripts/aws-tf-test.sh, so CI can cache it by
# version and skip the download.
#
#   scripts/tf-providers.sh latest          prints the newest version on the
#                                           registry, the one terraform init
#                                           picks for main.tf (no version pin)
#   scripts/tf-providers.sh DIR [VERSION]   terraform init of a module that
#                                           needs VERSION (default: latest),
#                                           in the pinned Terraform image;
#                                           DIR gets its providers folder
#
# No AWS account is used.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

latest() {
  curl -fsS https://registry.terraform.io/v1/providers/hashicorp/aws |
    python3 -I -c 'import json,sys; print(json.load(sys.stdin)["version"])'
}

case "${1:-}" in
  "") echo "usage: $0 latest | DIR [VERSION]" >&2; exit 2 ;;
  latest) latest; exit 0 ;;
esac
out="$1"
ver="${2:-$(latest)}"
[[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a provider version: $ver" >&2; exit 1; }

mkdir -p "$BUILD"
work="$(mktemp -d "$BUILD/tf-providers.XXXXXX")"
trap 'rm -rf "$work"' EXIT
cat >"$work/main.tf" <<TF
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "= $ver" }
  }
}
TF
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e TF_IN_AUTOMATION=1 \
  -v "$work:/w" -w /w "$TERRAFORM_IMAGE" init -backend=false -input=false -no-color >/dev/null
rm -rf "$out"
mkdir -p "$(dirname "$out")"
mv "$work/.terraform/providers" "$out"
log "tf-providers: hashicorp/aws $ver in $out"
