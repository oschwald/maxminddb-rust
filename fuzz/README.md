# Fuzzing

The fuzz suite uses [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and
requires a nightly Rust toolchain.

Install the runner and execute either target from the repository root:

```console
cargo install cargo-fuzz --locked
cargo +nightly fuzz run decode
cargo +nightly fuzz run reader
```

`decode` sends arbitrary data-section values through both Serde decoding and
database verification. `reader` exercises database opening, verification,
lookups, full decoding, path decoding, and network iteration. It tests each
input both as an arbitrary database and as mutations to a small valid database,
which lets the fuzzer reach deeper parsing paths without a separate seed corpus.

For a bounded local smoke test, pass libFuzzer options after `--`:

```console
cargo +nightly fuzz run decode -- -max_total_time=30
cargo +nightly fuzz run reader -- -max_total_time=30
```

Crashes are written under `fuzz/artifacts/`. Minimize a crash with `cargo fuzz
tmin`, then add the minimized input or an equivalent focused case to the normal
test suite as a permanent regression test.
