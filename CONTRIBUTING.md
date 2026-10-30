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
- Get at least one reviewer approval. The author does not count.
- Squash when merging; the final commit follows the rules above.

## Module rules

- Keep modules independent, with their own build files, tests and README.
  Use public packages and local `go.mod` replacements between Go modules.
- Keep test helpers and development-only code out of production builds.
- Add fuzz tests for parsers of untrusted input.
- Update dependency pins and checksums together.

## What never goes into the repo

Never commit secrets, real cloud account or project IDs, personal paths
or private infrastructure names. Use fake values in examples and tests.
`make check` scans for private keys, tokens and AWS account IDs only, so
review your diff before pushing.

## Security issues

Do not report vulnerabilities in public issues or pull requests. Follow
[SECURITY.md](SECURITY.md).
