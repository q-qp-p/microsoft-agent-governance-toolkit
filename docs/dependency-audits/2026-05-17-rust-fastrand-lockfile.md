# Rust fastrand Lockfile Refresh

## Which Dependencies Changed And Why

- `agent-governance-rust/Cargo.lock` updates transitive crate `fastrand` from
  `2.4.0` to `2.4.1`.
- `fastrand` is pulled transitively by `tempfile`; it is not a direct
  workspace dependency.
- The update removes the Cargo packaging warning for yanked `fastrand 2.4.0`
  while keeping the same compatible `2.x` dependency line selected by Cargo.

## Security Advisory Relevance

- No CVE or RustSec advisory was identified for this lockfile refresh.
- The dependency review bot reported no vulnerabilities or license issues for
  the changed lockfile.
- The bot's OpenSSF Scorecard details for `cargo/fastrand` noted upstream
  project hygiene gaps such as missing packaging workflow, token-permission
  findings, no fuzzing signal, and no security policy signal. Those are
  upstream project posture notes rather than a vulnerability in this PR.

## Breaking Change Risk Assessment

- Risk is low: this is a patch-level transitive update from `2.4.0` to
  `2.4.1`.
- The Rust workspace release tests, strict clippy, package verification, and
  runnable examples all passed after the lockfile refresh.
