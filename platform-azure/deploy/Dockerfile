# Runner image for ACI confidential containers (platform-azure/deploy/README.md). One
# image serves every signer of every operator: it holds the release runner
# and nothing else. Build it with build-image.sh.
#
# The runner flags are not here. ACI replaces the image entrypoint with the
# container's `command` (Override entrypoint in container instance, ACI
# docs), and az confcom puts that command into the CCE policy, which the Key
# Vault release policy pins by hash. The command of aci-template.json holds
# the flags that are the same for everyone; the policy allows that exact
# command only, so a group that runs the image with another command does
# not start.
#
# The operator's values (chain config, client CA, MAA host, vault and key,
# mark and state stores, signer name, network entry names) are in the signer's
# setup (research/setup-phase.md in the threshold-signer-poc repo). It comes in the
# environment value SIGNER_SETUP, base64, from an ARM parameter without a
# default, which az confcom turns into a wildcard rule. The runner reads it
# first, checks it with the shared decoder and puts setup_hash in its
# identity. Other bytes give a runner with another setup_hash. Its keys are
# derived from the released key and setup_hash, so such a runner opens
# nothing this signer sealed or wrapped.
#
# Mutual TLS 1.3 on the runner port, with the setup's client CA and a key
# made in the TEE at each start and bound to the attested identity. Shares
# arrive sealed to the attested HPKE key (the release runner has no
# plaintext import). The setup's mark log is the clone protection.
#
# The mode of the runner is set here, with COPY --chmod, and build-image.sh
# gives the context file the same mode. COPY without --chmod keeps the mode
# of the file in the context, which follows the builder's umask; the same
# inputs then gave two image digests, so two CCE policy hashes, depending
# on who built the image.
FROM scratch
COPY --chmod=0555 runner /runner
ENTRYPOINT ["/runner"]
