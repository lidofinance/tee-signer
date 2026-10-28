# Workload image for Confidential Space. One image for every operator
# (research/setup-phase.md in the threshold-signer-poc repo, "Design v2", section 1):
# the release runner and the flags that are the same for everyone.
#
# Every runner flag is fixed here. The launch policy below keeps the operator
# from overriding CMD or the environment, and the WIF provider pins this
# image's digest (deploy.sh wif-create). The operator's values (chain config,
# client CA, WIF provider, KMS key, identity audience, mark and state
# buckets, signer name) are in the signer's setup. The runner reads it at
# every start from the instance metadata attribute signer-setup (base64;
# deploy.sh vm-create sets it), not from tee-env-*, which would copy it into
# every attestation token. It checks it with the shared decoder and puts
# setup_hash in its identity. Other bytes give a runner with another
# setup_hash. Every KMS call carries setup_hash in its additional
# authenticated data, so such a runner opens nothing this signer sealed or
# wrapped.
#
# The runner is on the network here, so it serves mutual TLS 1.3 only: a key
# made in the TEE at each start, bound to the attested identity, and client
# certificates from the setup's client CA. Shares arrive sealed to the
# attested HPKE key (no -allow-import). Only port 7100 listens. The network
# entry (README, "Network entry") is outside the image: a firewall rule on
# the VM's external address. The setup's mark log is the clone protection
# (-record none).
# Clock: the NTS clock (-nts-clock, runner built with the tag nts), NTS-KE on
# TCP 4460 and NTP on UDP 123 and 4123 to the four operators of
# runner/nts.PublicServers, straight out through the VM's external address
# (the VPC's implied egress rule allows all). The three HTTPS-date URLs are
# its coarse check only.
# Identity tokens carry the audience signer-runner-identity, which the WIF
# provider does not accept, so a client that sees one cannot trade it for KMS
# access. Clients verify that audience.
# The mode is set here (COPY --chmod) and by build-image.sh on the context
# file, so the image digest that the WIF provider pins does not follow the
# builder's umask.
FROM scratch
COPY --chmod=0555 runner /runner
# Launch policy labels (Google "launch policies" reference). The defaults are
# strict already. They are spelled out so a reviewer sees them.
# No allow_env_override: the container token lists env values (claims
# container.env and container.env_override), so a secret passed that way
# would reach every client that asks for an identity.
# No allow_mount_destinations: tee-mount offers tmpfs only, and the runner
# keeps its store on the container's own file system.
LABEL "tee.launch_policy.allow_cmd_override"="false"
LABEL "tee.launch_policy.allow_capabilities"="false"
LABEL "tee.launch_policy.allow_cgroups"="false"
LABEL "tee.launch_policy.monitoring_memory_allow"="never"
# "always" lets the operator read the runner's log in Cloud Logging during the
# test. Use "never" for production shares.
LABEL "tee.launch_policy.log_redirect"="always"
# Confidential Space opens only the ports the image declares: without this
# the launcher logs "Exposed Ports: map[]" and the host firewall drops 7100.
EXPOSE 7100/tcp
ENTRYPOINT ["/runner", \
  "-platform", "gcp", \
  "-setup", "platform", \
  "-listen", "tcp:0.0.0.0:7100", \
  "-state-dir", "/var/lib/signer", \
  "-restart-floor=true", "-persist-watermarks=false", \
  "-record", "none", \
  "-nts-clock", \
  "-nts-coarse-urls", "https://cloudkms.googleapis.com/,https://sts.googleapis.com/,https://www.cloudflare.com/", \
  "-log-json"]
