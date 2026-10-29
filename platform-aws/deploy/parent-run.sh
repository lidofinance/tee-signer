#!/usr/bin/env bash
# Runs on the Nitro parent EC2 instance (Amazon Linux 2023, enclave
# support enabled at launch). x86_64 or arm64: the documented choice is a
# Graviton c6g.large in eu-central-1. Starts the vsock proxies, the host
# agent, the enclave and the network entry: a forwarder from a TCP port to
# "vsock:${ENCLAVE_CID}:7100" that the Dirk fork connects to (README.md,
# "Network entry"). The forwarder copies bytes. The mutual TLS of the runner
# ends inside the enclave, so nothing on this instance needs a certificate
# or a key.
#
# Needs next to this script, all built for the arch of this instance
# (uname -m): runner-<arch>.eif (scripts/nitro-eif.sh), hostagent, forwarder
# and udprelay (scripts/build-runner.sh), and the instance role named in
# kms-key-policy.json. The enclave's NTS clock needs the four NTS-KE proxies
# (TCP 4460) and udprelay (NTP over vsock 7102 to UDP 123 and 4123), and the
# security group's egress for them (main.tf nts_egress).
#
# The EIF is the same for every signer (scripts/nitro-eif.sh). What makes it
# this signer is its setup (research/setup-phase.md in the threshold-signer-poc repo,
# section 3): the binary file signer-config setup (or signer-admin/cmd/setup-tool)
# makes, with the chain, the client CA, the KMS key and region, the mark
# bucket, the signer name and the key set hosts of the handover target's verifier (peer_attestation_hosts).
# The host agent checks it with the runner's decoder and hands it to the
# enclave at every start, before any KMS call. The vsock proxies follow
# from the same file over the fixed port map of platform-aws/deploy/enclave/Dockerfile
# (hostagent -proxy-routes).
#
# Settings (environment):
#   SETUP       required: the signer's binary setup (platform nitro). Check
#               it on the build machine first: setup-tool check -platform
#               nitro -chain governance/chains/CHAIN.json SETUP. The setup's key
#               release region must be the region of this instance: the
#               enclave dials kms.<region>... by name through the proxies.
#   CPU_COUNT   vCPUs for the enclave. Default 2, or 1 on an instance with
#               fewer than 4 vCPUs (c6g.large has 2): the parent keeps one.
#   MEMORY_MIB  memory for the enclave, default 512.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENCLAVE_CID="${ENCLAVE_CID:-16}"
STATE_DIR="${STATE_DIR:-/var/lib/signer-runner}"
EIF="${EIF:-$HERE/runner-$(uname -m).eif}"
ENTRY_PORT="${ENTRY_PORT:-7100}" # TCP port of the network entry
CPU_COUNT="${CPU_COUNT:-$(( $(nproc) >= 4 ? 2 : 1 ))}"
MEMORY_MIB="${MEMORY_MIB:-512}"
[ -f "$EIF" ] || { echo "$EIF: no such file (build it with scripts/nitro-eif.sh for $(uname -m))" >&2; exit 1; }
for tool in hostagent forwarder udprelay; do
  [ -x "$HERE/$tool" ] || { echo "$HERE/$tool: no such program (scripts/build-runner.sh builds it)" >&2; exit 1; }
done
[ -n "${SETUP:-}" ] || { echo "set SETUP to the signer's binary setup (signer-config setup, or signer-admin/cmd/setup-tool encode)" >&2; exit 1; }
SETUP="$(cd "$(dirname "$SETUP")" && pwd)/$(basename "$SETUP")"
# The routes of the setup, one "PORT HOST HOSTPORT" line each. The agent
# refuses a setup the runner would refuse, and one for another platform.
ROUTES="$("$HERE/hostagent" -setup "$SETUP" -proxy-routes)" || { echo "$SETUP: refused (see above)" >&2; exit 1; }
echo "setup $SETUP, proxy routes:"
echo "$ROUTES"

# 1. Nitro CLI and allocator (AWS docs: nitro-enclave-cli-install.html).
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
sudo usermod -aG ne "$USER" || true
sed -e "s/^cpu_count:.*/cpu_count: $CPU_COUNT/" -e "s/^memory_mib:.*/memory_mib: $MEMORY_MIB/" \
  "$HERE/allocator.yaml" | sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null
sudo systemctl enable --now nitro-enclaves-allocator.service

# 2. vsock-proxy, one per route of the setup: KMS and STS of its region
#    (8000, 8001), the third coarse-time host (8002), the mark bucket (8004),
#    the NTS-KE servers of the NTS clock (8005 to 8008) and the setup's
#    peer_attestation_hosts, the hosts the attestation verifier fetches key sets from
#    (8010 up to 8025, in the setup's order). TLS ends in the enclave. The
#    allowlist holds these destinations only (platform-aws/deploy/vsock-proxy.yaml is
#    an example of what it gets). A peer endpoint on another port than 443
#    also needs an egress rule in the security group (main.tf allows TCP 443).
{
  echo "# Written by parent-run.sh from the setup's routes (hostagent -proxy-routes)."
  echo "allowlist:"
  while read -r port host hostport; do
    echo "- {address: $host, port: $hostport}"
  done <<<"$ROUTES"
} | sudo tee /etc/nitro_enclaves/vsock-proxy.yaml >/dev/null
while read -r port host hostport; do
  nohup vsock-proxy "$port" "$host" "$hostport" --config /etc/nitro_enclaves/vsock-proxy.yaml \
    >"/tmp/vsock-proxy-$port.log" 2>&1 &
done <<<"$ROUTES"

# 2b. NTP of the NTS clock: vsock 7102 to UDP, to the allowlist of the four
#     operators only (udprelay -h; the defaults are that list). It sees
#     only NTS-protected packets: it can delay or drop them, not forge them.
nohup "$HERE/udprelay" -listen vsock:any:7102 >/tmp/udprelay.log 2>&1 &

# 3. Host agent: the setup, sealed blobs and instance role credentials over
#    vsock 7101. record/writer-credentials.kms must be in the store before
#    the first start: the mark bucket's S3 writer credentials, encrypted
#    under the enclave's KMS key by the key admin (README.md, "Clone guard").
#    If the runner fails, it sends its error line to the agent before it
#    exits (a refused setup too): see $STATE_DIR/last-exit.txt and
#    /tmp/hostagent.log.
sudo mkdir -p "$STATE_DIR"
sudo chown "$USER" "$STATE_DIR"
[ -f "$STATE_DIR/record/writer-credentials.kms" ] || \
  echo "warning: $STATE_DIR/record/writer-credentials.kms missing; the enclave will refuse to start" >&2
nohup "$HERE/hostagent" -listen vsock:any:7101 -dir "$STATE_DIR" -creds imds -setup "$SETUP" \
  >/tmp/hostagent.log 2>&1 &

# 4. The enclave. Never use --debug-mode or --attach-console for real
#    keys: in debug mode all PCRs read as zero and the KMS policy fails
#    closed (AWS docs: set-up-attestation.html). Check the Measurements of
#    describe-enclaves against build/nitro/build-enclave-<arch>.json on the
#    build machine: PCR0, PCR1 and PCR2 must be equal. For an EIF built on
#    another arch (arm64 built on x86_64) only this launch shows that the
#    PCRs the build machine computed are the ones the hardware reports.
nitro-cli run-enclave --eif-path "$EIF" --cpu-count "$CPU_COUNT" --memory "$MEMORY_MIB" --enclave-cid "$ENCLAVE_CID"
nitro-cli describe-enclaves

# 5. Network entry: TCP $ENTRY_PORT to the enclave's vsock port 7100 (the
#    runner's -listen, baked into the image). A plain byte forwarder: no TLS,
#    no key, no CA. It dials the enclave for each connection, so it can start
#    before or after the enclave. Another TCP forwarder does the same job,
#    for example
#      socat TCP-LISTEN:7100,fork,reuseaddr VSOCK-CONNECT:16:7100
#    Who may reach the port is set in the security group (entry_cidrs in
#    main.tf). That limits exposure. It is not what keeps the runner safe:
#    the mutual TLS inside the enclave is.
nohup "$HERE/forwarder" -listen "tcp:0.0.0.0:$ENTRY_PORT" -to "vsock:$ENCLAVE_CID:7100" \
  >/tmp/forwarder.log 2>&1 &
