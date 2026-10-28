# Contributing

Everyone works through branches and pull requests, maintainers included.
Nothing lands on `main` without review.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/), with the
module as the scope:

```
fix(slashing-log): refuse a foreign record on a conditional create conflict
feat(platform-aws): check the recipient attestation condition of the key policy
test(tee-signer): red test for a share loaded before its history
```

- The scope is the folder name of the module the change is in. A change
  that spans modules gets one commit per module where it can be split;
  otherwise use the module that holds the reason for the change.
- Repo-wide changes (scripts, Makefile, CI, top-level docs) use `build`,
  `ci` or `docs`, without a scope.
- Subject in lower case, no period at the end, at most 72 characters. Say
  what the code does after the change.
- The body says why, and names the finding or issue it fixes.
- A change to a stored or wire format marks the type with `!` and has a
  `BREAKING CHANGE:` footer. It bumps the format version, comes with a
  migration test, and its PR lists every reader of the format.

Every commit is signed (GPG or SSH, with a key on your GitHub account).
Branch protection refuses unsigned commits.

## Pull requests

- One change per PR. Branch names: `fix/<topic>`, `feat/<topic>`,
  `test/<topic>`, `docs/<topic>`.
- The PR description says what changes, why, how it was tested, and which
  modules it touches.
- CI must pass: `make check` and `make test-modules` at least, `make test`
  for changes to a runner build.
- Review: at least one approval from a code owner of every module the PR
  touches. A change to a module marked PERIMETER in
  [SECURITY-SCOPE.md](SECURITY-SCOPE.md) needs two approvals, and the
  author does not count.
- Merge by squash. The squash commit follows the commit rules above.

## Module rules

- Each module keeps its own `go.mod` (or C or Rust build), tests and
  README.
- A module imports another module only through its public packages, and
  lists it in its `go.mod` with a `replace` line to `../<module>`.
  `scripts/check-imports.sh` checks both.
- Test helpers go in `devkit` or next to the code as `_test.go` files.
  Product code imports nothing of `devkit` except `devkit/lockorder`.
- New parsers of untrusted bytes come with a fuzz target.
- Code under `third_party/` is vendored at a pin. Change it only to move
  the pin, in its own PR, with the checksums updated.

## What never goes into the repo

Secrets, real cloud account or project IDs, personal paths and private
infrastructure names. `scripts/check-forbidden.sh` checks every file; run
`make check` before you push.
