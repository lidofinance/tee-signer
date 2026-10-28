# Enclave image for nitro-cli build-enclave. One image for every operator
# (research/setup-phase.md in the threshold-signer-poc repo, "Design v2", section 1):
# it holds the runner and the flags that are the same for everyone, so
# PCR0 to PCR2 are the same for every signer and the image gets audited
# once. The host cannot pass arguments to an enclave, and must not be able
# to.
#
# The operator's values are not here: the chain config, the client CA, the
# KMS key and region, the mark bucket and the signer name come from the
# signer's setup. The runner reads it at every start from the host agent on
# the parent (-setup platform: SETUP over vsock 7101, before any KMS call),
# checks it with the shared decoder and computes setup_hash. A host that
# hands over other bytes gets a runner with another setup_hash. Every KMS
# call carries setup_hash in its encryption context, so such a runner gets
# neither this signer's sealing key nor its mark log keys, and its
# IDENTITY shows the other setup_hash.
# The proxy routes follow from the setup's region, mark bucket and peer
# endpoints over the fixed port map below; parent-run.sh starts the proxies
# from the same setup (hostagent -proxy-routes).
#
# The parent instance forwards traffic into the enclave over vsock and is
# not trusted. The runner therefore serves mutual TLS 1.3 on its vsock
# listener, with the client CA of the setup.
#
# Restart floor margin: max_epochs_ahead + 1 of the setup. Shares arrive
# only sealed to the enclave's attested HPKE key (no -allow-import). The
# mark log of the setup (S3 with Object Lock) is the clone protection; the
# DynamoDB clone guard and -record-key are gone (-record none). The S3
# writer credentials are KMS-encrypted to this enclave and kept by the
# parent at record/writer-credentials.kms (platform-aws/deploy/README.md).
# -mark-create, -state-create and -record-create stay off: the runner
# refuses them with -setup.
#
# Clock: the NTS clock (-nts-clock; runner-aws is built with the tag nts).
# The enclave has no network. Fixed vsock port map on the parent (CID 3):
#
#   7101  host agent (store, credentials, the setup)
#   7102  udprelay: NTP of the NTS clock, to an allowlist only
#   8000  kms.REGION.amazonaws.com:443
#   8001  sts.REGION.amazonaws.com:443
#   8002  www.cloudflare.com:443 (the third coarse-time host)
#   8004  BUCKET.s3.REGION.amazonaws.com:443 (the mark bucket)
#   8005 to 8008  NTS-KE, TCP 4460, of the four operators of runner/nts.PublicServers
#   8010 to 8025  the setup's peer_endpoints in their order, at most 16: the
#                 hosts the DKG peer verifiers fetch key sets from (an Azure
#                 peer's MAA host, Google's Confidential Space hosts)
#
# The three HTTPS-date URLs are the NTS clock's coarse check; {region} is
# the one value the runner fills in, with the setup's key release region.
# The parent can delay or drop this traffic, not forge it: TLS and the NTS
# authenticator end in here.
#
# Build context: a directory holding runner (static, from
# scripts/build-runner.sh). scripts/nitro-eif.sh prepares it. The mode is set
# here (COPY --chmod) and by scripts/nitro-eif.sh on the context file.
# Without it the image, and so PCR0 and PCR2, would follow the builder's umask.
FROM scratch
COPY --chmod=0555 runner /runner
ENTRYPOINT ["/runner", \
  "-platform", "nitro", \
  "-setup", "platform", \
  "-listen", "vsock:any:7100", \
  "-state-dir", "/tmp/unused", \
  "-restart-floor=true", "-persist-watermarks=false", \
  "-record", "none", \
  "-nts-clock", \
  "-nts-coarse-urls", "https://kms.{region}.amazonaws.com/,https://sts.{region}.amazonaws.com/,https://www.cloudflare.com/", \
  "-log-json"]
