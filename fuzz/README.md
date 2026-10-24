# Standalone fuzzing

This is an independent Cargo workspace. CI compile-checks both targets but does
not run fuzz campaigns. It uses `libfuzzer-sys`, the parent crate by path, and the
same pinned `declio` Git revision as the parent. Keep that revision synchronized
when the parent changes it. The lockfile is checked in; generated outputs are
ignored.

## Targets and limits

- `pdb`: accepts at most 16 MiB, opens an MSF/PDB from a borrowed byte slice,
  then independently attempts info, TPI, IPI, and DBI. Successful metadata reads
  enable `/names`, both type hash streams, publics, globals, symbols, section
  headers, frame data, FPO, and module streams. Failure of an optional getter
  does not prevent the others from being tried. Visits up to 128 modules and
  256 records per collection, including module symbols and decoded C13
  subsections. Stream getters themselves decode their entire requested stream.
- `records`: accepts at most 64 KiB and independently calls `Decode` on
  `TypeRecord`, `IdRecord`, and `SymbolRecord` using the same input. Input starts
  with the little-endian record kind followed by its payload; there is **no**
  outer record-length prefix or harness selector byte. Trailing bytes and decode
  errors are allowed.

Errors are normal fuzz outcomes; panics are not caught. Oversized inputs are
rejected, not truncated. Input and traversal caps reduce routine work but do
**not** impose a hard in-process memory or CPU bound: malicious counts/lengths
can cause allocations or substantial work inside a decoder before it returns.
Do not run untrusted campaigns without process-level resource limits/isolation.

## Build and run

Use a supported cargo-fuzz platform, preferably Linux (or Linux in WSL2 on
Windows), with a nightly Rust toolchain, a C++ compiler, and `cargo-fuzz`:

```sh
rustup toolchain install nightly --profile minimal --no-self-update
cargo install cargo-fuzz --locked
# Run these commands from the repository root.
cargo check --locked --manifest-path fuzz/Cargo.toml
mkdir -p fuzz/corpus/pdb fuzz/corpus/records fuzz/output
cp tests/corpus/*.pdb fuzz/corpus/pdb/
```

Seed the container target with copies of the existing `tests/corpus/*.pdb`, not
with an in-place writable corpus pointing at the test fixtures. Inputs larger
than 16 MiB need a deliberately revised cap; do not truncate valid seed PDBs.
For `records`, use raw individual CodeView records (kind + payload), not whole
PDB files or their outer length prefixes. The target can also start empty.

Example bounded campaigns from the repository root on Linux/WSL2:

```sh
timeout --kill-after=10s 10m cargo +nightly fuzz run pdb -- -max_len=16777216 -timeout=5 -rss_limit_mb=2048 -max_total_time=540
timeout --kill-after=10s 10m cargo +nightly fuzz run records -- -max_len=65536 -timeout=5 -rss_limit_mb=2048 -max_total_time=540
```

`-timeout` limits each test case; `-max_total_time` limits the fuzzing campaign;
GNU `timeout` also bounds the surrounding build/run process. libFuzzer's RSS
limit is monitored, not a hard OS allocation limit. In addition, run the entire
process tree in a memory-limited container/cgroup (for example 3 GiB with swap
also constrained) or a Windows Job Object with memory and time limits. Account
for compiler and sanitizer overhead when choosing limits. A virtual-address
space `ulimit` can conflict with sanitizer shadow-memory reservations; prefer
RSS/cgroup limits. Native Windows sanitizer/cargo-fuzz support varies, so a
plain `cargo check` is only a compilation check, not a fuzz campaign.

Generated corpora, artifacts, coverage, build files, and optional logs under
`fuzz/output/` stay local. Do not redistribute seeds without checking their
provenance and licensing.

## Reproduce, minimize, and retain regressions

1. Save the target, toolchain, command, limits, and original artifact. Reproduce
   with the same target and resource limits, for example:
   `cargo +nightly fuzz run pdb fuzz/artifacts/pdb/crash-<hash>`.
2. Minimize with `cargo +nightly fuzz tmin pdb fuzz/artifacts/pdb/crash-<hash>`
   (use `records` for record failures), under external memory/time limits too.
   Confirm the minimized input still triggers the same failure. Minimize timeout
   and OOM cases with consistent limits; do not mistake another failure for the
   original bug.
3. Fix the parser separately and add a deterministic regression test with the
   smallest necessary, provenance-safe input. Prefer synthetic byte construction
   when practical. Any retained binary belongs in an explicitly reviewed test
   fixture location, not an ignored generated fuzz directory. Keep minimized
   regressions after the fix; do not commit bulk corpora, raw artifacts, or logs.
