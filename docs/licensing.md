# Licence packaging

The root `LICENSE` applies to first-party code and documentation unless a file
states otherwise. Third-party dependencies, vendored sources and imported test
fixtures keep their existing licences and attribution notices. Preserve those
notices when copying or redistributing them.

`scripts/build-runner.sh` writes `<binary>.licenses/` beside each runner and host
tool. Distribute this directory with the binary, including in release archives.
The cloud image builders copy the runner's bundle to `/licenses` and verify the
files against the build context. The bundle contains:

- `LICENSE`: this project's Apache-2.0 licence.
- `THIRD_PARTY_NOTICES`: licence, notice, copyright and patent files from the
  binary's Go modules, the Go standard library's vendored dependencies, and
  blst when linked. The NTS client is on the Go standard library and adds no
  notices of its own.

The notice collector uses the binary's Go build information and cached module
sources, without fetching from the network. It fails if a dependency has no
notice files or requires a separate native-code review. Some upstream notice
sets cover more code than the binary uses; the bundle is not an audit scope list.
Build with the same Go toolchain used to collect the notices. If a packaged Go
toolchain stores `LICENSE` elsewhere, set `GO_LICENSE_DIR` to its directory.

When distributing a binary built another way, generate the bundle explicitly:

```sh
python3 scripts/bundle-licenses.py build/x86_64/bin/runner-aws
```

Review additional components supplied by your build environment or overlay.
`SIGNER_EXTRA_LICENSE_DIR` adds licence and notice files from a distributor's
directory to the bundle. In particular, the static GNU/Linux builds also link
the C runtime and may link compiler runtime code. Their notices and any source
or relinking materials required by their terms must accompany a binary release;
collecting application dependency notices alone does not satisfy those duties.
The Nitro EIF also contains the kernel and bootstrap from the pinned Nitro CLI
blobs, whose redistribution terms and corresponding source need a separate
release review. These components are not Go modules.

Adding notice files to an image changes its digest and, for Nitro, its enclave
measurements. Rebuild and approve the resulting image through the normal image
and handover process.
