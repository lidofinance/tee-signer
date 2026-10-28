# Security policy

## Report a vulnerability

Do not open a public issue or pull request for a security problem.

Report it to PLACEHOLDER-SECURITY-CONTACT, or through GitHub's private
vulnerability reporting on this repository once it is enabled.

Please include:

- the module and the commit you looked at,
- what an attacker needs (host access, an operator or approver key, network
  position, nothing),
- what they get: a key or share, a slashable signature, a signature without
  approval, a stopped signer,
- steps or a test that shows it.

We answer within PLACEHOLDER-RESPONSE-TIME and keep you informed until the
fix is out. Please give us time to fix the problem before you publish it.

## Scope

Every module of this repo. Bugs that let untrusted input past the modules
marked PERIMETER in [SECURITY-SCOPE.md](SECURITY-SCOPE.md) matter most:
key custody, slashing safety and approval checks.

This code is not audited and not for production use yet. Test keys and test
networks only.
