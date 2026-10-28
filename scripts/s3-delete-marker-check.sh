#!/usr/bin/env bash
# Checks on real S3 what the mark log's fake assumes (issue #5 R3): does a
# conditional create (PutObject with If-None-Match: *) go through when the
# current version of the key is a delete marker? And does
# ListObjectVersions show the hidden version and the marker, which
# s3log's check after each create relies on?
#
# It makes a temporary bucket with versioning (no Object Lock, so it can
# be emptied and deleted), writes a "clone" record, hides it behind a
# delete marker, tries the conditional create again, lists the versions,
# then deletes every version, every marker and the bucket. Nothing else
# is touched. It costs a few requests.
#
#   AWS_PROFILE=... AWS_REGION=eu-central-1 bash scripts/s3-delete-marker-check.sh
#
# Needs AWS CLI v2 with put-object --if-none-match, and jq. Not run by any
# test target: run it by hand.
set -euo pipefail

region="${AWS_REGION:?set AWS_REGION}"
bucket="signer-r3-check-$(date -u +%Y%m%d%H%M%S)-$RANDOM"
key="marks/check/00000000000000000002"
tmp="$(mktemp -d)"

cleanup() {
  set +e
  echo "cleanup: deleting every version and delete marker of s3://$bucket, then the bucket"
  aws s3api list-object-versions --bucket "$bucket" --output json 2>/dev/null |
    jq -c '[(.Versions // [])[], (.DeleteMarkers // [])[]] | .[] | {Key, VersionId}' |
    while read -r obj; do
      aws s3api delete-object --bucket "$bucket" --key "$(jq -r .Key <<<"$obj")" \
        --version-id "$(jq -r .VersionId <<<"$obj")" >/dev/null
    done
  aws s3api delete-bucket --bucket "$bucket" --region "$region" && echo "cleanup: bucket deleted"
  rm -rf "$tmp"
}
trap cleanup EXIT

echo "bucket s3://$bucket in $region"
if [ "$region" = us-east-1 ]; then
  aws s3api create-bucket --bucket "$bucket" --region "$region" >/dev/null
else
  aws s3api create-bucket --bucket "$bucket" --region "$region" \
    --create-bucket-configuration LocationConstraint="$region" >/dev/null
fi
aws s3api put-bucket-versioning --bucket "$bucket" --versioning-configuration Status=Enabled

printf 'clone record' >"$tmp/clone"
printf 'honest record' >"$tmp/honest"

echo "1. the clone's conditional create of $key"
aws s3api put-object --bucket "$bucket" --key "$key" --body "$tmp/clone" --if-none-match '*' --output json | jq -c .

echo "2. a second conditional create while the clone's record is current (want 412 PreconditionFailed)"
if aws s3api put-object --bucket "$bucket" --key "$key" --body "$tmp/honest" --if-none-match '*' >/dev/null 2>"$tmp/err"; then
  echo "   UNEXPECTED: it went through"
else
  echo "   refused: $(tr '\n' ' ' <"$tmp/err")"
fi

echo "3. a delete marker over the clone's record"
aws s3api delete-object --bucket "$bucket" --key "$key" --output json | jq -c .

echo "4. the honest runner's conditional create over the delete marker"
if aws s3api put-object --bucket "$bucket" --key "$key" --body "$tmp/honest" --if-none-match '*' --output json >"$tmp/put" 2>"$tmp/err"; then
  echo "   WENT THROUGH: real S3 lets a conditional create pass a delete marker, as the fake does"
  jq -c . "$tmp/put"
else
  echo "   refused: $(tr '\n' ' ' <"$tmp/err")"
  echo "   real S3 refuses it; the R3 attack needs another path"
fi

echo "5. ListObjectVersions of the key (s3log's check after a create reads this)"
aws s3api list-object-versions --bucket "$bucket" --prefix "$key" --output json |
  jq -c '{versions: [(.Versions // [])[] | {VersionId, IsLatest, Size}], delete_markers: [(.DeleteMarkers // [])[] | {VersionId, IsLatest}]}'
echo "   s3log refuses (ErrHidden, then ErrLost) when it sees more than one version or any delete marker"
