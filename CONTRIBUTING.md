# Contributing

Everyone works through branches and pull requests, maintainers included.
Nothing lands on `main` without review.

## Getting started

Follow the [build instructions](README.md#build) and read the README of
the module you want to change. Run the commands below from the repo root.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/) with the
module as the scope, for example:

```
fix(slashing-log): stop when another runner writes the next record
```

- Keep commits focused and buildable. Use the module folder name as the
  scope; repo-wide changes use `build`, `ci` or `docs` without a scope.
- Use a lower-case subject, at most 72 characters, without a final period.
  Explain why in the body and link a related issue, if any.
- Stored or wire format changes need a version bump, a migration test,
  `!` and a `BREAKING CHANGE:` footer. List affected readers in the PR.

Every commit is signed (GPG or SSH, with a key on your GitHub account).

## Pull requests

- One change per PR. Explain what changes, why, the affected modules and
  how you tested it. Note any checks you could not run.
- Run `make check` and `make test-modules`; also run `make test` for runner
  build changes. All required CI checks must pass.
  On a pull request CI tests and fuzzes only the modules the change
  touches and the modules that depend on them (`scripts/ci-scope.sh`).
  A docs-only change runs only the guards. The e2e tests run when code
  that goes into a runner changes, or `tests/`; the gateway e2e test
  when `gateway/` or `web3signer-api/` changes; the signer-core suites
  when `signer-core/` or `markformat/` changes. A change to a shared
  input (`Makefile`, `scripts/`, `.github/`, `devkit/`, C or Rust code)
  tests everything. So do a push to main and a manual run.
  On a pull request the `aws-terraform` job runs `scripts/tf-validate.sh`
  and `scripts/aws-tf-test.sh` (a mock provider, no AWS account) only when
  a file under `platform-aws/deploy/` other than docs changes, or those
  scripts. A nightly run (`fuzz-nightly.yml`) fuzzes every target for 30 s.
- Get at least one reviewer approval. The author does not count.
- Squash when merging; the final commit follows the rules above.

## Module rules

- Keep modules independent, with their own build files, tests and README.
  Use public packages and local `go.mod` replacements between Go modules.
- Keep test helpers and development-only code out of production builds.
- Add fuzz tests for parsers of untrusted input. Each target calls
  `fuzzcheck.Watch(t)` (devkit) first; `make fuzz` refuses one that does not.
- Update dependency pins and checksums together.

## What never goes into the repo

Never commit secrets, real cloud account or project IDs, personal paths
or private infrastructure names. Use fake values in examples and tests.
`make check` scans for private keys, tokens and AWS account IDs only, so
review your diff before pushing.

## Security issues

Do not report vulnerabilities in public issues or pull requests. Follow
[SECURITY.md](SECURITY.md).
