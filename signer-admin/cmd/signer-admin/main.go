// Command signer-admin is the admin tool of the cloud signers
// (research/admin-tool.md): it builds the setups of one cluster, changes
// their config with approver-signed updates (research/setup-phase.md, "Easy
// config update track") and drafts, signs and pushes orders. It is the
// Dirk fork's signer-config, moved to the cloud repo with the same
// commands and flags, and builds from the cloud repo's packages: the codecs
// of backend/ and the client of attest/runnerclient, which checks each
// signer's attestation and setup pins on every connection. A runner takes
// the admin messages only from a client certificate of the admin role
// (docs/protocol.md, "Client roles"), so each connection file names an
// admin certificate.
//
//	signer-admin setup [-build default|testnet] [-allow-gcp-unsafe-single-key] -out DIR FILE
//	    Read a human setup file with one [signer NAME] section per signer,
//	    draw one random cluster_id, write DIR/NAME.setup for each signer and
//	    print each setup_sha256. -build testnet: the runners are testnet
//	    builds, so a time lock above their cap (1800 s) is refused.
//	    -allow-gcp-unsafe-single-key: every GCP signer's setup accepts
//	    that the signer holds keys alone (1 of 1), which is unsafe there
//	    (setupwire.UnsafeSingleKeyWarning); without it a file with one GCP
//	    signer is refused, and a setup with the acceptance gets a WARNING line.
//	signer-admin pin -cluster cluster.json
//	    Read each signer's IDENTITY, check that it shows the setup built for
//	    it, and write setup_sha256 into its cloud.json.
//	signer-admin status -cluster cluster.json
//	    One line per signer: setup, version and hash per group, pending
//	    update with its effective time, approver set, clock. Marks signers
//	    that differ from the rest.
//	signer-admin draft -cluster cluster.json -group locked|open [-margin 10m] [-out update.bin] FILE
//	    Read the new values of one group, check that every signer is at the
//	    same version, print the diff and write the body to sign (update.bin)
//	    and the values it replaces (update.bin.active).
//	signer-admin show [-active FILE] FILE
//	    Decode a body or a signed update offline and print its values, the
//	    diff against the active values and the body hash.
//	signer-admin sign -key FILE|openpgp:KEYGRIP [-hashed] [-expect-sha256 HEX] [-out FILE] update.bin
//	    Sign the body with one approver key: a hex seed file (mode 0600)
//	    or an Ed25519 key in gpg-agent, such as a YubiKey's OpenPGP
//	    signing key, which signs the hashed form only. -expect-sha256 takes
//	    the direct form's sha256 that show printed and refuses another body.
//	signer-admin approver-key -key FILE|openpgp:KEYGRIP | -openpgp FILE [-fingerprint HEX]
//	    Print an approver's public key as the setup's approvers line,
//	    from the key, gpg-agent's copy of a card key's public key or an
//	    exported OpenPGP public key. Needs no card.
//	signer-admin assemble [-active FILE] [-out update.signed] update.bin SIG...
//	    Check the signatures against the active approvers (and, for a
//	    rotation, every new key) and write the signed update.
//	signer-admin push -cluster cluster.json [-raise-min] update.signed
//	    Send the signed update to every signer and print what each one says.
//	signer-admin handover-draft -cluster cluster.json -signer NAME -target-cloud FILE
//	                             [-target-setup-sha256 HEX] [-target-name NAME] [-not-after 12h] [-out handover.bin]
//	    Draft a handover order (handoverdraft.go): the source signer NAME hands
//	    its shares to the one target of FILE's settings and setup_sha256.
//	    show, sign, assemble and push take it as they take an update;
//	    push sends it to the source only.
//
//	signer-admin probe -cluster cluster.json [-signers NAME,...]
//	    Tell, per signer, whether admin messages from its connection file's
//	    certificate pass the runner's role check (adminops.go): a message
//	    type no runner serves tells a role-checking image from an older
//	    one, an empty CONFIG_UPDATE tells the admin role from the others.
//	    Changes nothing. Run it before every order, handover or import.
//	signer-admin import-draft -cluster cluster.json -signer NAME -split FILE [-not-after 12h] [-out import.bin]
//	    Draft an import order for one target signer: its setup_sha256, t, n,
//	    its share index and, per validator, the hash of the t commitments.
//	    show, sign and assemble take it as they take an order.
//	signer-admin import -cluster cluster.json -signer NAME -order import.signed -shares FILE -commitments FILE
//	    Probe the role, check the runner's attestation, seal each share of
//	    FILE (mode 0600) to the attested import key and send
//	    IMPORT_SHARE_SEALED under the order.
//	signer-admin exit-draft -cluster cluster.json -pubkey 0x.. -index N -epoch E -balance GWEI [-not-after 24h] [-out exit.bin]
//	    Draft an exit approval (the TA's 152-byte layout) with a fresh
//	    nonce. show prints what approvers check on the chain before they
//	    sign; push sends signed approvals to every signer, at most 8 a run.
//	signer-admin issue-client-cert -ca-cert FILE -ca-key FILE -role admin|attest|signing -name CN -out DIR
//	signer-admin issue-client-cert -ca-cert FILE -ca-key FILE -make-intermediate ROLE -name CN -out DIR
//	    Issue one client certificate of a role, or a role intermediate from
//	    a root (issue.go).
//
// sign -hashed signs the hash-then-sign form of any body: 32 bytes, the
// SHA-256 of the kind's hash context and SHA-256 of the direct message
// (docs/protocol.md, "Approver signatures: direct and hashed"). assemble
// and the runners take either form per signature.
//
// pin, status, draft and push take -signers NAME,... to work on part of the
// cluster, and -timeout for each signer (default 30 s). handover-draft takes
// -timeout; -signers there drafts an order of part of the cluster.
//
// cluster.json lists the signers of one cluster, with paths relative to it:
//
//	{
//	  "signers": [
//	    {"name": "azure-1", "cloud": "azure-1/cloud.json", "setup": "setups/azure-1.setup"}
//	  ],
//	  "updates": "updates"
//	}
//
// cloud is the signer's connection file (address, client_cert, client_key,
// attestation), as attest/runnerclient reads it; its client certificate
// has the admin role. setup
// is the binary setup that signer-admin setup wrote for it. updates is the
// folder where push keeps a copy of each update a signer took (default
// "updates"); draft finds the active values there, because the runner has no
// message that returns them.
//
// A runner of the testnet build (backend/buildflavor, research on
// devnets and test networks) runs its governance time locks in minutes: a
// 2-minute default time lock, a 7-minute images minimum. The connection
// refuses one unless its cloud.json sets "allow_testnet_build": true. status
// and pin print each signer's build (build=default or build=testnet), draft
// and handover-draft compute the waits with the signers' build and refuse signers
// of two builds, and show and sign, which see no runner, name the testnet
// wait when it differs.
package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if !errors.Is(err, errReported) {
			fmt.Fprintln(os.Stderr, "signer-admin:", err)
		}
		os.Exit(1)
	}
}

// errReported is the error of a subcommand that printed its failures per
// signer already.
var errReported = errors.New("signer-admin: failed for some signers")

// now is the clock of the tool. Tests replace it.
var now = time.Now

// toolRand draws cluster_id and the salts.
var toolRand io.Reader = rand.Reader

const usage = `usage:
  signer-admin setup [-build default|testnet] [-allow-gcp-unsafe-single-key] -out DIR FILE
  signer-admin pin -cluster cluster.json [-signers NAME,...]
  signer-admin status -cluster cluster.json [-signers NAME,...]
  signer-admin draft -cluster cluster.json -group locked|open [-margin 10m] [-out update.bin] FILE
  signer-admin show [-active FILE] FILE
  signer-admin sign -key FILE|openpgp:KEYGRIP [-hashed] [-expect-sha256 HEX] [-out FILE] update.bin|handover.bin|import.bin|exit.bin
  signer-admin approver-key -key FILE|openpgp:KEYGRIP | -openpgp FILE [-fingerprint HEX]
  signer-admin assemble [-active FILE] [-out update.signed] update.bin SIG...
  signer-admin push -cluster cluster.json [-raise-min] [-signers NAME,...] update.signed|handover.signed
  signer-admin handover-draft -cluster cluster.json -signer NAME -target-cloud FILE [-target-setup-sha256 HEX] [-target-name NAME] [-not-after 12h] [-out handover.bin]
  signer-admin probe -cluster cluster.json [-signers NAME,...]
  signer-admin import-draft -cluster cluster.json -signer NAME -split FILE [-not-after 12h] [-out import.bin]
  signer-admin import -cluster cluster.json -signer NAME -order import.signed -shares FILE -commitments FILE
  signer-admin exit-draft -cluster cluster.json -pubkey 0x.. -index N -epoch E -balance GWEI [-not-after 24h] [-out exit.bin]
  signer-admin issue-client-cert -ca-cert FILE -ca-key FILE -role admin|attest|signing|-make-intermediate ROLE -name CN -out DIR`

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	cmds := map[string]func([]string, io.Writer) error{
		"setup": cmdSetup, "pin": cmdPin, "status": cmdStatus, "draft": cmdDraft,
		"show": cmdShow, "sign": cmdSign, "assemble": cmdAssemble, "push": cmdPush,
		"handover-draft": cmdHandoverDraft,
		"probe":          cmdProbe, "import-draft": cmdImportDraft, "import": cmdImport, "exit-draft": cmdExitDraft,
		"issue-client-cert": cmdIssueClientCert, "approver-key": cmdApproverKey,
	}
	cmd, ok := cmds[args[0]]
	if !ok {
		return fmt.Errorf("unknown subcommand %q\n%s", args[0], usage)
	}
	return cmd(args[1:], out)
}
