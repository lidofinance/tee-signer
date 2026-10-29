# attestation-verify: attestation document verifiers

> **Early proof of concept.** Provided as is, without any warranty or guarantee.
> Not audited. Not for production or mainnet funds. Interfaces and formats will
> change without notice.

Package `github.com/lidofinance/tee-signer/attestation-verify` checks the documents the cloud runner returns
from `ATTEST` and `IDENTITY`, on the client side (the Dirk fork, the dealer,
an operator). `remote.DevVerifier` is the other verifier of this repo and
proves nothing. This package covers the three clouds:

| Platform | Document | Trust anchor | Signature |
|---|---|---|---|
| AWS Nitro | NSM attestation document, CBOR COSE_Sign1 | AWS Nitro Enclaves root G1, pinned by SHA-256 | ES384 by the leaf certificate in the document |
| GCP Confidential Space | OIDC token (JWT) | Google's key set for `https://confidentialcomputing.googleapis.com` | RS256 |
| Azure | Microsoft Azure Attestation token (JWT) | key set of one attestation provider (`<issuer>/certs`) | RS256 |

Every verifier fails closed. The caller must give the trust anchor, the
expected measurement (PCRs, image digest, host data or VM id) and a
freshness input (nonce, runtime data or maximum age); a missing one is
`ErrConfig`. Errors wrap sentinels (`ErrSignature`, `ErrChain`,
`ErrMeasurement`, `ErrNonce`, `ErrStale`, `ErrDebug`, ...) so callers and
tests can tell them apart. No verifier follows a key URL from the token
(`jku`, `x5u`, `x5c` in the JWT header are ignored).

## Use

Go:

```go
doc, err := attest.VerifyNitro(raw, attest.NitroOptions{
    PCRs:  map[int][]byte{0: pcr0, 1: pcr1, 2: pcr2},
    Nonce: nonce, // fresh per request
})
// doc.PCR(0..8), doc.UserData, doc.Nonce, doc.PublicKey
```

`identity.Config.Verify` has the signature of `remote.VerifyFunc`, so a
client can pass it where it passes `remote.DevVerifier` today. It fills
in the per-call binding the runner uses (code in `platform`):

- nitro: document `nonce` = client nonce, `user_data` =
  `backend.IdentityUserData(nonce, id)`.
- gcp: `eat_nonce` contains `hex(IdentityUserData)`.
- azure: `x-ms-sevsnpvm-reportdata` = sha256(`backend.MAARuntimeData(IdentityUserData)`),
  the JSON object `{"signer-runner-identity":"<hex>"}`, followed by 32
  zero bytes, because the runner puts the SHA-256 of the runtime data into
  the SNP report data (`platform-azure/azure/maa.go`; the protocol follows
  `pkg/attest/attest.go` in microsoft/confidential-sidecar-containers).

The azure branch is `azureid.Verify`, a small package of its own so that
`identity` and `runnerclient` check an Azure runner in one way.

### runnerclient: the client of the Dirk fork and the import tools

`runnerclient` builds a runner client from settings. The Dirk fork's cloud
adapter (`backend.cloud.config`), its `cloud-import` tool and
`signer-admin/cmd/share-import` all use it, so they apply the same checks:

```go
c := runnerclient.Connection{
    Address:    "tcp:signer-1:7100",
    ClientCert: "runner-client.pem", ClientKey: "runner-client-key.pem",
    Attestation: runnerclient.Attestation{
        Verifier:        "azure-maa",
        MAAHost:         "sharedweu.weu.attest.azure.net",
        CCEPolicySHA256: "<64 hex digits from deploy.sh policy>",
    },
}
cl, err := c.New() // refuses a bad or incomplete configuration
```

- Settings: `address` (tcp only; for an AWS runner the TCP port of the
  forwarder on the parent instance), `client_cert` (the certificate, then
  the intermediates if a CA below the pinned root issued it), `client_key`,
  optional `tls_key_pin`, and `attestation` with `verifier` (`dev`, `azure-maa`,
  `aws-nitro` or `gcp-cs`) and the settings of that verifier:

  | Verifier | Required | Optional |
  |---|---|---|
  | `azure-maa` | `maa_host`, `cce_policy_sha256` | `compliance_status` (default `azure-compliant-uvm`) |
  | `aws-nitro` | `nitro_pcrs`: PCR0, PCR1 and PCR2 by index, 96 hex digits each (`{"0": "...", "1": "...", "2": "..."}`) | more PCRs (3 for the parent role, 8 for the EIF signing certificate), `nitro_root_sha256` |
  | `gcp-cs` | `gcp_image_digest` (`sha256:` and 64 hex digits), `gcp_audience`, `gcp_hwmodels` (for example `GCP_AMD_SEV`, `GCP_INTEL_TDX`) | `gcp_issuer` (default `https://confidentialcomputing.googleapis.com`), `gcp_jwks_file` (a pinned key set instead of the issuer's), `gcp_service_account` |

  The command line tools take the same settings as flags: `-nitro-pcr
  INDEX=HEX` and `-gcp-hwmodel NAME`, both repeated, `-nitro-root-sha256`,
  `-gcp-image-digest`, `-gcp-audience`, `-gcp-issuer`, `-gcp-jwks-file`,
  `-gcp-service-account`.
- Setup settings, for every verifier (`setup.go`; research/setup-phase.md
  in the threshold-signer-poc repo, section 11). After the platform check, every
  connection checks the setup state of the verified identity:

  | Setting | Flag | Rule |
  |---|---|---|
  | `setup_sha256` | `-setup-sha256` | The runner's `setup_hash` must equal it. Required for a runner that reports a setup: without it such a runner is refused. A runner on the flag path (no setup; `setup_hash` is the SHA-256 of its `-config` file, every other field zero) is accepted without it. |
  | `min_locked_version`, `min_open_version` | `-min-locked-version`, `-min-open-version` | Optional, need `setup_sha256`. The group's effective version must be at least this. A pending update counts once its effective activation time has passed on the client's clock. |
  | `allow_unpinned_setup` | `-allow-unpinned-setup` | Tests only: accepts a runner with a setup and no `setup_sha256`. Refused with any verifier but `dev`, and together with `setup_sha256`. |

  The Dirk fork's adapter, `cloud-import` (again on the identity it seals
  each share to), `proof-check`, `share-import`, `identity-check`,
  and the runner's own handover checks all apply these rules. `WithVerified` hands each passed
  identity to the caller, and `SetupLog`, `DescribeSetup`,
  `EffectiveVersion` and `CheckPending` read the state for logs and tools.
- It refuses to build a client for a missing, unreadable, expired or
  mismatched client certificate and key, a non-tcp address, an unknown or
  missing verifier, a missing or malformed expected value, and the settings
  of one verifier on another. There is no setting that skips the
  verification. There is no setting for debug mode (Nitro: PCR0 to PCR2 all
  zero, GCP: `dbgstat` other than `disabled-since-boot`) or VMPL (Azure:
  must be 0), for accepting other PCRs or another root (Nitro), or for the
  checks of `swname`, `secboot` and STABLE support (GCP).
- `aws-nitro` trusts the AWS Nitro Enclaves root that `attest.NitroRootPEM`
  pins by its SHA-256, and no other. `nitro_root_sha256` lets the operator
  write down the fingerprint they expect; a build that pins another root
  refuses to start. An all-zero PCR0, PCR1 or PCR2 in the settings is
  refused, because it is the value of a debug-mode enclave.
- `gcp-cs` fetches the key set like `azure-maa` does, from
  `<gcp_issuer>/.well-known/openid-configuration`, unless `gcp_jwks_file`
  pins one (then it never asks the network and does not follow Google's key
  rotation). It refuses the STS audience and Workload Identity Federation
  resource names as `gcp_audience`, and `GCP_SHIELDED_VM` as a hardware
  model (a VM without memory encryption; from the model name, the claims
  page does not say). `GCP_AMD_SEV`, `GCP_AMD_SEV_ES` and `GCP_INTEL_TDX` are
  the other values on that page. For the three-cloud layout (Azure on AMD
  SEV-SNP, AWS Nitro, GCP) set `gcp_hwmodels` to `GCP_INTEL_TDX` only
  (`-gcp-hwmodel GCP_INTEL_TDX`), so one chip family never holds two
  shares. The verifier accepts every model on the list, so a list that
  names an AMD model would let a GCP runner on AMD hardware pass.
- On each connection it runs the handshake with the client certificate,
  IDENTITY with a fresh nonce, the verifier, and the check that the
  identity's TLS key hash is the key the handshake presented (signer-protocol/docs/protocol.md,
  "Channel binding").
- MAA key set (and the Confidential Space key set, unless pinned): fetched
  from `https://<maa_host>/.well-known/openid-configuration` at the first
  connection and kept for one hour. A token under an unknown key id causes
  one new fetch, at most every 30 seconds. After an hour a failed fetch
  fails the verification. These numbers are choices, not measurements.

Command line (`cmd/attest-verify`), prints the verified fields as JSON,
exit 0 verified, 1 refused, 2 usage:

```sh
cd attestation-verify && go build -o attest-verify ./cmd/attest-verify
./attest-verify -platform nitro -in doc.cbor -pcr 0=<hex> -pcr 1=<hex> -pcr 2=<hex> -nonce <hex>
./attest-verify -platform gcp -in token.jwt -aud signer-runner-identity -image-digest sha256:<hex> -max-age 5m
./attest-verify -platform azure -in token.jwt -issuer https://P.R.attest.azure.net \
    -compliance azure-compliant-uvm -hostdata <cce policy sha256> -skr-policy policy.json -max-age 5m
```

Without `-jwks`, the gcp and azure modes read
`<issuer>/.well-known/openid-configuration`, check that it names the same
issuer, and fetch `jwks_uri` over HTTPS. With `-jwks file` they use a
pinned set.

## What each verifier checks

AWS Nitro (`VerifyNitro`), following
[AWS: verifying the root of trust](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html):

1. COSE_Sign1, tagged (18) or untagged, exactly 4 elements; protected header
   alg ES384 (-35), no `crit`; 96-byte signature. CBOR with duplicate map
   keys, indefinite lengths, tags inside, or trailing bytes is refused.
2. Payload fields per the AWS CDDL: `digest` "SHA384", every PCR 48 bytes,
   PCR0 to PCR8 present, size limits on certificate, cabundle, nonce, user
   data and public key.
3. Chain: `cabundle[0]` must be a pinned root; the leaf must chain to it
   through the bundle at the verification time. The pinned root is
   `NitroRootPEM`; the package refuses to load if its SHA-256 is not
   `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`,
   the fingerprint AWS prints on the page above
   (`64:1A:03:21:...:79:BB:5B`). The root is CN=aws.nitro-enclaves,
   valid 2019-10-28 to 2049-10-28.
4. ES384 signature over the COSE Sig_structure with the leaf key.
5. Debug mode (PCR0, PCR1 and PCR2 all zero) refused unless `AllowDebug`.
6. Expected PCRs, nonce, user data; timestamp not older than `MaxAge` and
   not more than `Skew` in the future.

GCP Confidential Space (`VerifyConfidentialSpace`), claims from
[Google: token claims](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims)
and the
[OIDC discovery document](https://confidentialcomputing.googleapis.com/.well-known/openid-configuration):

- RS256 with a key from the configured set; `iss` (default
  `https://confidentialcomputing.googleapis.com`, configurable), `aud`,
  `exp`, `nbf`, `iat`, optional maximum age.
- `swname` = `CONFIDENTIAL_SPACE`, `secboot` = true, `dbgstat` =
  `disabled-since-boot` (`enabled` only with `AllowDebug`),
  `submods.confidential_space.support_attributes` contains `STABLE` (or
  the configured list), `submods.container.image_digest` in the allowed
  list, every expected nonce in `eat_nonce` (string or array), optional
  `hwmodel` and service account.

Azure (`VerifyMAA`), claims from
[Microsoft: claim sets](https://learn.microsoft.com/en-us/azure/attestation/claim-sets),
[token examples](https://learn.microsoft.com/en-us/azure/attestation/attestation-token-examples)
and [SKR policy examples](https://learn.microsoft.com/en-us/azure/confidential-computing/skr-policy-examples):

- RS256 with a key from the provider's set; `iss` equals the configured
  provider URL; `exp`, `nbf`, `iat`. `ParseJWKS` checks that each key's
  `n`/`e` equal its `x5c` certificate.
- SEV-SNP claims at the top level (ACI, and the HCL report shape) or under
  `x-ms-isolation-tee` when `x-ms-attestation-type` is `azurevm` (guest
  attestation): TEE type `sevsnpvm`, `x-ms-compliance-status` as configured
  (`azure-compliant-uvm` for ACI, `azure-compliant-cvm` for confidential
  VMs), `x-ms-sevsnpvm-is-debuggable` false, `x-ms-sevsnpvm-vmpl` 0.
- Workload: host data (the CCE policy hash on ACI), launch measurement, or
  VM id (`x-ms-azurevm-vmid`, or `x-ms-runtime.vm-configuration.vmUniqueId`
  in the HCL shape).
- Runtime data: report data = sha256(runtime data) + 32 zero bytes.
- Optional `ReleasePolicy`: evaluates a Key Vault release policy (our
  `platform-azure/deploy/skr-policy.json.tmpl`, rendered) the way the
  [policy grammar](https://learn.microsoft.com/en-us/azure/key-vault/keys/policy-grammar)
  describes: authority = `iss`, dotted claim paths, `anyOf`/`allOf`,
  `equals` only. A policy with another operator fails to parse. A string
  value also matches a bool or number claim with the same text (`"false"`,
  `"0"`), because our template writes them that way; the grammar page does
  not say how Key Vault compares types.

## Real formats or synthetic: what the tests cover

`go test ./...` in `attestation-verify/` runs offline with `GOPROXY=off`
when the modules it needs are in the module cache. Set
`RUNNER_AZURE_DEBUG_BIN` and `RUNNER_AWS_DEBUG_BIN` to the debug runners
`runner-azure-debugimport` and `runner-aws-debugimport` to run
`TestE2EAzureRunner` and the Nitro runner tests; without them those tests
skip. `scripts/test.sh` runs the package, and `make maa-test` runs the Azure
end-to-end test.

| What | Real | Synthetic |
|---|---|---|
| Nitro document parsing, chain to the real AWS root, ES384 signature | yes: 5 public sample documents (2 normal, 3 debug mode) verify against the pinned root at their own timestamps | yes: same format from a local P-384 test CA |
| Nitro refusals | on the real documents: flipped signature bit, flipped PCR1 bit, today's date (leaf expired), local CA as root, stale timestamp, wrong nonce, wrong PCR0, debug mode | also: wrong root, chain that names the root but does not reach it, expired leaf, wrong/missing PCR, stale and future timestamps, wrong user data, missing nonce, debug mode, ES256 header, missing PCR8, 32-byte PCR, duplicate CBOR key, trailing bytes, tagged form |
| GCP key set | Google's real key set (`testdata/jwks/`) parses; a locally signed token under a real Google kid fails with `ErrSignature` | yes |
| GCP token claims | no real token (none found in a public repository with a usable license) | layout from Google's claims reference; good token and tampered signature, tampered payload, wrong key, unknown kid, alg none/HS256/PS256, wrong issuer, wrong audience, expired, not yet valid, old iat, wrong digest, stale nonce, debug image, missing dbgstat, no STABLE, swname GCE, secboot false, hwmodel, service account, duplicate JSON member |
| MAA key set | the shared West Europe provider's real set (`testdata/jwks/`, 4 keys) parses, `n`/`e` match `x5c`; a locally signed token under a real kid fails with `ErrSignature` | yes |
| MAA token claims | no real token | layouts from Microsoft's SEV-SNP sample and SKR examples: ACI with our rendered SKR template, CVM guest attestation with SKR example 2 (VM id), HCL shape; refusals: tampered signature and payload, other provider's key, wrong issuer, expired, debuggable (top level and nested, also caught by the policy), missing is-debuggable, CVM token where ACI expected, wrong host data, stale runtime data, VMPL 2, non-SNP type, wrong VM id, policy for another authority, unsupported policy operators |
| identity adapter | no | Nitro, GCP and Azure identities bound like the runner does; replay with another nonce, changed HPKE key, STS audience, unconfigured platform refused |
| runnerclient | no | Against a fake runner (TLS 1.3, client certificate required) with the dev document and synthetic MAA tokens: 27 config refusals, wrong key pin, relay with its own key, replayed identity, wrong host data (another runner's policy), wrong issuer, debuggable, bad signature, signature by another key, VMPL 2, wrong compliance status, token for another nonce, dev document where azure-maa is expected, key set rotation and rate limit, unreachable key set. Against the debug runner on the azure platform with a fake SNP report, security context, metadata service, MAA and Key Vault (`TestE2EAzureRunner`, `RUNNER_AZURE_DEBUG_BIN`): a good identity verifies, the runner listens on its one port only, key pin, other policy hash, other provider host, CVM status, dev verifier, client certificate from another CA, four bad tokens (other policy, debuggable, bad signature, other key) are refused, and a refused key release stops the runner `aws-nitro` against synthetic NSM documents from a local test CA that the test makes the trust anchor, and against the real AWS sample document of `testdata/` (it chains to the real root, and is refused for its expired leaf): 30 config refusals and subtests, wrong PCR0, PCR1, PCR2 and PCR3, debug mode, bad signature, a CA the client does not trust, expired leaf, document for another nonce or user data, timestamp in the future, documents of the dev, Azure and GCP platforms, relay with its own key, wrong key pin, replayed identity, document of an earlier request under new identity fields. `gcp-cs` against synthetic tokens and a fake issuer that serves the key set: 42 config refusals and subtests, wrong image digest, wrong audience (the STS one too), wrong issuer, debug image, no `dbgstat`, plain GCE, secure boot off, no STABLE, Shielded VM, other hardware model, service account, expired, bad signature, signature by another key, nonce of another identity or none, another runner's image, documents of other platforms (refused before any key fetch), relay, wrong key pin, replay, key set rotation and rate limit, unreachable issuer, a pinned key set (no network, and one without the token's key), Google's real key set with a locally signed token. Setup pins (`setup_test.go`, dev document): config refusals, pin match and mismatch (no request sent after a mismatch), a runner with an unpinned setup refused and accepted with `allow_unpinned_setup`, a flag-path runner accepted unpinned and pinned to its config hash, minimum versions before and after a pending update's effective time, the pins in `NewVerifier`, a sealed import refused before sealing, `WithVerified`, the state helpers, flags and JSON names. |
| runnerclient, nitro platform | no | Against the debug runner on the nitro platform with a fake NSM (`TestE2ENitroRunner`, `RUNNER_AWS_DEBUG_BIN`): the runner's NSM-format document (testgen CA) passes `aws-nitro` and the TLS key hash in the identity matches the handshake key (channel binding); right and wrong key pin, client certificate from another CA, plain bytes, other PCR0, the AWS root in place of the test root, debug-mode PCRs, bad signature, other CA, other nonce, other user data and future timestamp all refused. A client certificate that is valid for one hour is refused by a runner whose clock is 2 hours ahead (`TestE2ENitroRunnerClientCertificateClock`). A client file with a leaf and an intermediate under the pinned root works, the leaf alone does not (`TestE2ENitroRunnerPinnedRootWithIntermediate`). The runner does not start on nitro without `-tls-client-ca` |
| CLI | the real Nitro sample: verified at its time, wrong PCR refused, today refused | |

Sources of the real files, with commit, license and hashes, are in
`testdata/nitro/*/SOURCE` and `testdata/jwks/SOURCE`:

- `testdata/nitro/blocky-nitrite/`: from
  [blocky/nitrite](https://github.com/blocky/nitrite) at `a6f5b6d`, MIT.
- `testdata/nitro/evervault/`: from
  [evervault/attestation-doc-validation](https://github.com/evervault/attestation-doc-validation)
  at `a296a77`, Apache-2.0.
- `testdata/jwks/`: key sets served by Google and by
  `sharedweu.weu.attest.azure.net`; `SOURCE` gives the fetch date. Both
  issuers rotate keys, so these files are for tests only.

No test verifies a document from a runner in a real TEE: that needs
a Nitro enclave, a Confidential Space VM or an ACI confidential container.
The closest is `TestE2EAzureRunner`. It verifies the IDENTITY
of our own debug runner (platform azure), but the SNP report, the metadata
service, MAA and Key Vault are fakes, and the MAA tokens are signed by a test
key. It shows that the runner and the verifier agree on the runtime data,
the user data and the TLS key binding, and that the runner's own requests
have the shape that the fakes expect. It says nothing about what real SNP
hardware, a real MAA provider and a real Key Vault return.

## Runner rules the verifiers rely on

These follow from the runner's and the vendors' code and docs. Unit tests
cover them; no test runs them on a cloud.

1. GCP identity tokens carry their own audience. A token with the STS
   audience (`https://sts.googleapis.com`) comes from the real workload, so
   it also meets the WIF provider's attribute condition: whoever holds it
   could exchange it at STS until it expires and call Cloud KMS decrypt as
   the workload, for example on the wrapped data key in the host-side store.
   The runner hands identity tokens to any client that asks for `IDENTITY`,
   and invariant 7 says Dirk is not trusted. So `attest_audience` defaults
   to `signer-runner-identity`, the runner refuses the STS audience and WIF
   resource names for identity and token-iat clock tokens, and the
   `Dockerfile` sets the audience. `platform-gcp/deploy/deploy.sh
   wif-create` keeps the STS audience for the runner's own KMS exchange
   only, and `platform-gcp/deploy/common.sh` stops if the identity audience
   equals it. `identity.Config.Verify` refuses the STS audience.
2. Azure: MAA takes runtime data of type `"JSON"` as a JSON object
   (Microsoft's sidecar sends it so in `pkg/common/maa.go`, a comment there
   says binary is not allowed). The runner sends
   `backend.MAARuntimeData(user data)`, the object
   `{"signer-runner-identity":"<hex>"}`, and `{"signer-runner-clock":"<hex>"}`
   for clock tokens, and refuses runtime data that is not a JSON object.
   `identity.Config.Verify` sets `RuntimeData` to `backend.MAARuntimeData` of
   the user data.

## Limits

- RS256 only for JWTs; PKI-type Confidential Space tokens (`x5c` chain to
  Google's attestation root) are not supported.
- TDX on Azure or GCP: claims not handled (`x-ms-attestation-type` must be
  `sevsnpvm` on Azure; GCP checks no TEE-specific claim).
- No revocation checks: AWS says to disable CRLs for Nitro; MAA and Google
  rotate keys instead.
- Key sets: the verifier trusts whatever set the caller gives it. Pin the
  issuer URL and fetch over TLS, or pin a set and refresh it before the
  issuer rotates.
- Azure guest attestation tokens carry more debug claims
  (`x-ms-azurevm-*`) that this verifier does not check; their names were
  not confirmed on a Microsoft page. A release policy (`-skr-policy`) can
  require them.
