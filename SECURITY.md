# Security policy

## Report a vulnerability

The Lido contributors appreciate your efforts to disclose your findings responsibly and will make every effort to acknowledge your contributions.

To report a security issue, please use the [Lido Bug Bounty program on Immunefi](https://immunefi.com/bounty/lido). This platform enables efficient tracking and response to vulnerabilities while offering rewards for valid submissions.

> [!IMPORTANT]
> Please DO NOT file a public issue or pull request on GitHub or disclose the vulnerability publicly in any way before it has been addressed by the Lido contributors.

Please include:

- the module and the commit you looked at,
- what an attacker needs (host access, an operator or approver key, network
  position, nothing),
- what they get: a key or share, a slashable signature, a signature without
  approval, a stopped signer,
- steps or a test that shows it.

## Scope

Please refer to the [Lido Bug Bounty page on Immunefi](https://immunefi.com/bounty/lido) for details on what is considered within the bug bounty program's scope.

Issues affecting key custody, slashing safety or approval checks are especially
important in this repository.

This code is not audited and not for production use yet. Test keys and test networks only.

## Process

1. Submit your report through the Immunefi platform.
2. The Lido contributors will evaluate your report and may request additional information or clarification.
3. Once validated, the team will work on a fix and coordinate the release process.
4. After the fix is deployed, a security advisory will be published, and your contribution will be acknowledged (if you wish to be credited).
