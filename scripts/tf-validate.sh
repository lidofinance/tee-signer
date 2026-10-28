#!/usr/bin/env bash
# terraform validate on platform-aws/deploy/main.tf and platform-aws/deploy/target/main.tf (the
# second parent and key of a handover target), in the pinned Terraform
# image. No AWS account is used and nothing is planned or applied. The
# provider is downloaded once into build/tf*/.terraform (terraform init) and
# reused. TF_PLUGIN_DIR (a folder with registry.terraform.io/hashicorp/aws/...,
# for example another checkout's build/tf/.terraform/providers) installs it
# from there instead, with no download.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

validate() { # validate SRC DIR
  local src="$1" dir="$2" plug=()
  mkdir -p "$dir"
  cp "$src" "$dir/main.tf"
  if [ -n "${TF_PLUGIN_DIR:-}" ]; then
    [ -d "$TF_PLUGIN_DIR/registry.terraform.io" ] || { echo "TF_PLUGIN_DIR=$TF_PLUGIN_DIR has no registry.terraform.io folder" >&2; exit 1; }
    plug=(-v "$TF_PLUGIN_DIR:/plugins:ro")
  fi
  tf() {
    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -e TF_IN_AUTOMATION=1 "${plug[@]}" \
      -v "$dir:/w" -w /w "$TERRAFORM_IMAGE" "$@"
  }
  if [ ! -d "$dir/.terraform/providers" ]; then
    if [ -n "${TF_PLUGIN_DIR:-}" ]; then
      tf init -backend=false -input=false -no-color -plugin-dir=/plugins >/dev/null
    else
      tf init -backend=false -input=false -no-color
    fi
  fi
  echo "${src#"$ROOT"/}:"
  tf validate -no-color
  tf version -json | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print("terraform", d["terraform_version"], d.get("provider_selections"))'
}

validate "$ROOT/platform-aws/deploy/main.tf" "$BUILD/tf"
validate "$ROOT/platform-aws/deploy/target/main.tf" "$BUILD/tf-target"
