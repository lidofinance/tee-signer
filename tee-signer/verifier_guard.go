//go:build (platform_aws || platform_azure || platform_gcp) && runnerbuild && !verifierselect

// A build set that must not compile. A cloud runner built without
// verifierselect links every attestation verifier of
// attestation-verify/runnerclient, the dev one included, which accepts
// unsigned documents. scripts/common.sh (runner_tags) sets verifierselect
// with the platform tag of every runner build, and runnerbuild, which only
// the runner builds have: the module tests build with the platform tags
// alone and link every verifier on purpose. A build that hits this fails
// on the undefined name below, which says why.

package main

var _ = cloud_runner_builds_need_verifierselect
